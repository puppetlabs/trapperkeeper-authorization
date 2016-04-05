(ns puppetlabs.trapperkeeper.authorization.acl
  (:require [schema.core :as schema]))

;; Schemas

(def Extensions
  "Schema for representing SSL Extensions. Maps from a keyword shortname to a
  string value."
  {schema/Keyword schema/Str})

(def ExtensionRule
  "Schema for defining an SSL Extension auth rule."
  {schema/Keyword (schema/conditional
                   sequential? [String]
                   :else String)})

(def ACEChallenge
  "Pertinent authorization information extracted from a request used during
  authz rule enforcement."
  {:certname String
   :extensions Extensions})

(def ACEConfig
  "Schema for representing the configuration of an ACE."
  (schema/pred #(or (nil? (schema/check String (:certname %)))
                    (nil? (schema/check ExtensionRule (:extensions %))))
               "ACE Config Value"))

(def AuthType (schema/enum :allow :deny))

(def ACEValue
  (schema/conditional
   map? ExtensionRule
   string? String
   sequential? [String]
   :else schema/Regex))

(def ACE
  "An authorization entry matching a network or a domain"
  {:auth-type AuthType
   :match (schema/enum :string :regex :backreference :extensions)
   :value ACEValue})

(def ACL
  "An ordered list of authorization Entry"
  #{ACE})

(schema/defn deny? :- schema/Bool
  [ace :- ACE]
  (= (ace :auth-type) :deny))

(schema/defn allow? :- schema/Bool
  [ace :- ACE]
  (= (ace :auth-type) :allow))

;; ACE comparison

(schema/defn ace-compare :- schema/Int
  "Compare two ACEs.  Deny ACEs always come before allow ACEs.

  For two ACEs of the same type - deny or allow - the 'b' entry always comes
  before the 'a' entry.  When used as a comparator for a sorted set, this
  ensures that entries of the same type are ordered first-in, first-out."
  [a :- ACE
   b :- ACE]
  (cond
    (deny? b) 1
    (deny? a) -1
    :else 1))

(def empty-acl (sorted-set-by ace-compare))

;; ACE creation

(schema/defn ^:private split-domain :- [String]
  "Given a domain string, split it on '.' and reverse it. For examples,
  'sylvia.plath.net' becomes ('net' 'plath' 'sylvia'). This is used for domain
  matching."
  [domain :- String]
  (-> domain
      (clojure.string/lower-case)
      (clojure.string/split #"\.")
      reverse))

(schema/defn ^:always-validate new-domain :- ACE
  "Creates a new ACE for a domain"
  [auth-type :- AuthType
   {:keys [certname extensions]} :- ACEConfig]
  (cond
    ;; SSL Extensions
    (map? extensions)
    {:auth-type auth-type
     :match :extensions
     :value extensions}

    ; global
    (= "*" certname)
    {:auth-type auth-type
     :match :regex
     :value #"^*$"}

    ; exact domain
    (re-matches #"^(\w[-\w]*\.)+[-\w]+$" certname)
    {:auth-type auth-type
     :match :string
     :value (split-domain certname)}

    ; *.domain.com
    (re-matches #"^\*(\.(\w[-\w]*)){1,}$" certname)
    (let [host_sans_star (vec (drop-last (split-domain certname)))]
      {:auth-type auth-type
       :match :string
       :value host_sans_star})

    ; backreference
    (re-find #"\$\d+" certname)
    {:auth-type auth-type
     :match :backreference
     :value (split-domain certname)}

    ; opaque string
    (re-matches #"^\w[-.@\w]*$" certname)
    {:auth-type auth-type
     :match :string
     :value [certname]}

    ; regex
    (re-matches #"^/.*/$" certname)
    {:auth-type auth-type
     :match :regex
     :value (clojure.string/replace certname #"^/(.*)/$" "$1")}

    :else
    (throw (Exception. (str "invalid domain value: " certname)))))

;; ACE matching

(schema/defn ^:private match-domain? :- schema/Bool
  "Checks that name matches the given ace"
  [{:keys [value match]} :- ACE
   to-match :- schema/Str]
  (let [match-split-domain (split-domain to-match)]
    (if (= :regex match)
      (boolean (re-find (re-pattern value) to-match))
      (every? (fn [[a b]] (= a b)) (map vector value match-split-domain)))))

(schema/defn ^:private substitute-backreference :- String
  "substiture $1, $2... by the same index in the captures vector"
  [in :- String
   captures :- [String]]
  (clojure.string/replace in #"\$(\d+)" #(nth captures (- (read-string (second %)) 1))))

(schema/defn interpolate-backreference :- ACE
  "change all possible backreferences in ace patterns to values from the
  capture groups"
  [{:keys [match auth-type] :as ace} :- ACE
   captures :- [String]]
  (if (= match :backreference)
    (new-domain auth-type
                {:certname (clojure.string/join "." (map #(substitute-backreference % captures)
                                                         (reverse (ace :value))))})
    ace))

(schema/defn match-extensions? :- schema/Bool
  "Returns true if the provided SSL extension map matches the configured ACE.
  All of the keys in the ACE must appear in the extensions map and, if the value
  for a key in the ACE is a list, at least one of the listed values must be set
  in the incoming extensions map.

  Note the behavior in the following scenario: If an ACE specifies
  {:deny {:extensions {:pp_env 'test'
                       :pp_image 'bad image'}}}

  *ONLY* a request with both :pp_env set to 'test' and :pp_image set to 'bad
  image' would be denied. If *any* request with :pp_env set to 'test' is to be
  denied, it needs a standalone deny rule."
  [ace :- ACE
   extensions :- Extensions]
  (let [match-key (fn [k]
                    (let [ace-value (get (:value ace) k)
                          ext-value (get extensions k false)]
                      (if ext-value
                        (if (sequential? ace-value)
                          (some (partial = ext-value) ace-value)
                          (= ace-value ext-value))
                        false)))]
    (every? match-key (keys (:value ace)))))

(schema/defn match? :- schema/Bool
  "Returns true if the given value matches the given ace"
  [{:keys [match] :as acl-ace} :- ACE
   {:keys [certname extensions]} :- ACEChallenge]
  (cond
    (= :extensions match)
    (if (nil? extensions)
      false
      (match-extensions? acl-ace extensions))

    :else
    (if (nil? certname)
      false
      (match-domain? acl-ace certname))))

;; ACL creation

(schema/defn add-ace :- ACL
  "Add a new host ACE to this acl"
  ([auth-type :- AuthType
    value :- ACEConfig]
    (add-ace empty-acl auth-type value))
  ([acl :- ACL
    auth-type :- AuthType
    value :- ACEConfig]
    (conj acl (new-domain auth-type value))))

(schema/defn allow :- ACL
  "Allow a new value to an ACL"
  ([value :- ACEConfig]
    (add-ace :allow value))
  ([acl :- ACL
   value :- ACEConfig]
    (add-ace acl :allow value)))

(schema/defn deny :- ACL
  "Deny a new value to an ACL"
  ([value :- ACEConfig]
    (add-ace :deny value))
  ([acl :- ACL
    value :- ACEConfig]
    (add-ace acl :deny value)))

;; ACL result

(schema/defn allowed? :- schema/Bool
  "Returns true if the name is allowed by acl, otherwise returns false"
  ([acl :- ACL
    incoming-ace :- ACEChallenge]
    (allowed? acl incoming-ace []))
  ([acl :- ACL
    incoming-ace :- ACEChallenge
    captures :- [schema/Str]]
   (let [interpolated-acl (map #(interpolate-backreference % captures) acl)
         match (some #(if (match? % incoming-ace) % false) interpolated-acl)]
      (if match
        (allow? match)
        false))))
