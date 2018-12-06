(ns puppetlabs.trapperkeeper.authorization.acl
  (:require [clojure.set :refer [intersection]]
            [schema.core :as schema]
            [puppetlabs.ssl-utils.core :refer [subject-alt-name-oid]]
            [puppetlabs.i18n.core :refer [trs]]))

;; Schemas
(def RBACRule
  "Schema for defining an RBAC Permission"
  {:permission schema/Str})

(def OIDMap
  "Mapping of string OIDs to shortname keywords. Used to update an incoming
  request with a shortname -> value extensions map."
  {schema/Str schema/Keyword})

(def Extensions
  "Schema for representing SSL Extensions as they come in on a request's
  certificate. Maps from a keyword shortname to a string value by default with
  special casing for more complex keys. The only special key supported now is
  :subject-alt-name which contains a map of keyword to lists of strings (if
  present at all)."
  {schema/Keyword schema/Str
   (schema/optional-key :subject-alt-name)
   {(schema/optional-key :dns-name) [schema/Str]
    (schema/optional-key :ip) [schema/Str]
    (schema/optional-key :other-name) [schema/Str]
    (schema/optional-key :rfc822-name) [schema/Str]
    (schema/optional-key :x400-address) [schema/Str]
    (schema/optional-key :directory-name) [schema/Str]
    (schema/optional-key :edi-party-name) [schema/Str]
    (schema/optional-key :uri) [schema/Str]
    (schema/optional-key :registered-id) [schema/Str]}})

(defn ^:private one-or-many [schema]
  (schema/conditional
   sequential? [schema]
   :else schema))

(def ExtensionRule
  "Schema for defining an SSL Extension auth rule."
  {schema/Keyword (one-or-many schema/Str)
   (schema/optional-key :subject-alt-name)
   {(schema/optional-key :dns-name) (one-or-many schema/Str)
    (schema/optional-key :ip) (one-or-many schema/Str)
    (schema/optional-key :other-name) (one-or-many schema/Str)
    (schema/optional-key :rfc822-name) (one-or-many schema/Str)
    (schema/optional-key :x400-address) (one-or-many schema/Str)
    (schema/optional-key :directory-name) (one-or-many schema/Str)
    (schema/optional-key :edi-party-name) (one-or-many schema/Str)
    (schema/optional-key :uri) (one-or-many schema/Str)
    (schema/optional-key :registered-id) (one-or-many schema/Str)}})

(def ACEChallenge
  "Pertinent authorization information extracted from a request used during
  authz rule enforcement."
  {:certname schema/Str
   :extensions Extensions})

(def ACEConfig
  "Schema for representing the configuration of an ACE."
  (schema/pred #(or (nil? (schema/check schema/Str (:certname %)))
                    (nil? (schema/check ExtensionRule (:extensions %))))
               "ACE Config Value"))

(def AuthType (schema/enum :allow :deny))

(def ACEValue
  (schema/conditional
   map? ExtensionRule
   string? schema/Str
   sequential? [schema/Str]
   :else schema/Regex))

(def ACE
  "An authorization entry matching a network or a domain"
  {:auth-type AuthType
   :match (schema/enum :string :regex :backreference :extensions)
   :value ACEValue})

(def ACL
  "An ordered list of authorization Entry"
  #{ACE})

(def default-oid-map
  "A default map of string OIDs to keyword names. These should be standard OIDs
  that any user of tk-auth might be interested in using. This map should be
  respected anywhere oid-maps are consulted."
  {subject-alt-name-oid :subject-alt-name})

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

(schema/defn ^:private split-domain :- [schema/Str]
  "Given a domain string, split it on '.' and reverse it. For examples,
  'sylvia.plath.net' becomes ('net' 'plath' 'sylvia'). This is used for domain
  matching."
  [domain :- schema/Str]
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
    (throw (Exception. (trs "invalid domain value: {0}" certname)))))

;; ACE matching

(schema/defn ^:private match-domain? :- schema/Bool
  "Checks that name matches the given ace"
  [{:keys [value match]} :- ACE
   to-match :- schema/Str]
  (let [match-split-domain (split-domain to-match)]
    (if (= :regex match)
      (boolean (re-find (re-pattern value) to-match))
      (every? (fn [[a b]] (= a b)) (map vector value match-split-domain)))))

(schema/defn ^:private substitute-backreference :- schema/Str
  "substiture $1, $2... by the same index in the captures vector"
  [in :- schema/Str
   captures :- [schema/Str]]
  (clojure.string/replace in #"\$(\d+)" #(nth captures (- (read-string (second %)) 1))))

(schema/defn interpolate-backreference :- ACE
  "change all possible backreferences in ace patterns to values from the
  capture groups"
  [{:keys [match auth-type] :as ace} :- ACE
   captures :- [schema/Str]]
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
  denied, it needs a standalone deny rule.

  If the :subject-alt-name key is present in the extension map, a match is done
  for each givenName key in the incoming request. For example, given a rule like
  this:

  {:extensions {:subject-alt-name {:dns-name [\"foobar.org\" \"barbaz.net\"]
                                   :ip \"192.168.0.1\"}}}

  these requests would match:

  {:extensions {:subject-alt-name {:dns-name [\"foobar.org\" \"slimjim.net\"]}}}

  {:extensions {:subject-alt-name {:dns-name [\"snapinto.org\" \"slimjim.net\"]
                                   :ip       [\"192.168.0.1\"]}}}

  and these would not match:

  {:extensions {:subject-alt-name {:dns-name [\"snapinto.org\" \"slimjim.net\"]
                                   :ip       [\"192.168.0.0\"]}}}

  {:extensions {:subject-alt-name {:ip       [\"192.168.0.0\"]}}}"
  [oid-map :- OIDMap
   ace :- ACE
   extensions :- Extensions]
  (let [oid-map' (merge default-oid-map oid-map)
        wrap-scalar (fn [x] (if (sequential? x) x [x]))
        match-key (fn [k]
                    (let [ace-value (get (:value ace) k)
                          ;; potentially translate from oid -> shortname
                          k' (get oid-map' (name k) k)
                          ext-value (get extensions k' false)
                          given-names-match? (fn [k] (not
                                                      (empty?
                                                       (intersection (set (get ext-value k))
                                                                     (set (wrap-scalar
                                                                           (get ace-value k)))))))]
                      (if ext-value
                        (if (= :subject-alt-name k')
                          (reduce (fn [acc key] (or acc (given-names-match? key)))
                                  false
                                  (keys ext-value))
                          (not (nil? (some (partial = ext-value)
                                           (wrap-scalar ace-value)))))
                        false)))]
    (every? match-key (keys (:value ace)))))

(schema/defn match? :- schema/Bool
  "Returns true if the given value matches the given ace"
  ([acl-ace :- ACE
    incoming-ace :- ACEChallenge]
   (match? acl-ace incoming-ace {}))
  ([{:keys [match] :as acl-ace} :- ACE
    {:keys [certname extensions]} :- ACEChallenge
    oid-map :- OIDMap]
   (cond
     (= :extensions match)
     (if (nil? extensions)
       false
       (match-extensions? oid-map acl-ace extensions))

     :else
     (if (nil? certname)
       false
       (if-let [alt-names (some-> extensions :subject-alt-name :dns-name)]
         (reduce (fn [acc domain] (or acc (match-domain? acl-ace domain)))
                 false
                 (conj alt-names certname))
         (match-domain? acl-ace certname))))))

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
    (allowed? acl incoming-ace {}))
  ([acl :- ACL
    incoming-ace :- ACEChallenge
    options :- {(schema/optional-key :captures) [schema/Str]
                (schema/optional-key :oid-map) OIDMap}]
   (let [captures (get options :captures [])
         oid-map' (get options :oid-map {})
         interpolated-acl (map #(interpolate-backreference % captures) acl)
         match (some #(if (match? % incoming-ace oid-map') % false) interpolated-acl)]
      (if match
        (allow? match)
        false))))
