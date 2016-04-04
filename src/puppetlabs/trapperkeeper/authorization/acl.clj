(ns puppetlabs.trapperkeeper.authorization.acl
  (:require [schema.core :as schema]))

;; Schemas

(def AuthType (schema/enum :allow :deny))
(def EntryPattern (schema/conditional
                   string? String
                   sequential? [String]
                   :else schema/Regex))

(def Entry
  "An authorization entry matching a network or a domain"
  {:auth-type AuthType
   :match (schema/enum :string :regex :backreference)
   :pattern EntryPattern})

(def ACL
  "An ordered list of authorization Entry"
  #{Entry})

(schema/defn deny? :- schema/Bool
  [ace :- Entry]
  (= (ace :auth-type) :deny))

(schema/defn allow? :- schema/Bool
  [ace :- Entry]
  (= (ace :auth-type) :allow))

;; ACE comparison

(schema/defn ace-compare :- schema/Int
  "Compare two ACEs.  Deny ACEs always come before allow ACEs.

  For two ACEs of the same type - deny or allow - the 'b' entry always comes
  before the 'a' entry.  When used as a comparator for a sorted set, this
  ensures that entries of the same type are ordered first-in, first-out."
  [a :- Entry
   b :- Entry]
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

(schema/defn new-domain :- Entry
  "Creates a new ACE for a domain"
  [type :- AuthType
   pattern :- schema/Str]
  (cond
    ; global
    (= "*" pattern)
    {:auth-type type
     :match :regex
     :pattern #"^*$"}

    ; exact domain
    (re-matches #"^(\w[-\w]*\.)+[-\w]+$" pattern)
    {:auth-type type
     :match :string
     :pattern (split-domain pattern)}

    ; *.domain.com
    (re-matches #"^\*(\.(\w[-\w]*)){1,}$" pattern)
    (let [host_sans_star (vec (drop-last (split-domain pattern)))]
      {:auth-type type
       :match :string
       :pattern host_sans_star})

    ; backreference
    (re-find #"\$\d+" pattern)
    {:auth-type type
     :match :backreference
     :pattern (split-domain pattern)}

    ; opaque string
    (re-matches #"^\w[-.@\w]*$" pattern)
    {:auth-type type
     :match :string
     :pattern [pattern]}

    ; regex
    (re-matches #"^/.*/$" pattern)
    {:auth-type type
     :match :regex
     :pattern (clojure.string/replace pattern #"^/(.*)/$" "$1")}

    :else
    (throw (Exception. (str "invalid domain pattern: " pattern)))))

;; ACE matching

(schema/defn match-name? :- schema/Bool
  "Checks that name matches the given ace"
  [{:keys [pattern match]} :- Entry
   to-match :- schema/Str]
  (let [match-split-domain (split-domain to-match)]
    (if (= :regex match)
      (boolean (re-find (re-pattern pattern) to-match))
      (every? (fn [[a b]] (= a b)) (map vector pattern match-split-domain)))))

(defn- substitute-backreference
  "substiture $1, $2... by the same index in the captures vector"
  [in captures]
  (clojure.string/replace in #"\$(\d+)" #(nth captures (- (read-string (second %)) 1))))

(defn interpolate-backreference
  "change all possible backreferences in ace patterns to values from the
  capture groups"
  [ace captures]
  (if (= (:match ace) :backreference)
    (new-domain (ace :auth-type)
                (clojure.string/join "." (map #(substitute-backreference % captures)
                                              (reverse (ace :pattern)))))
    ace))

(schema/defn match? :- schema/Bool
  "Returns true if the given name matches the given ace"
  [ace :- Entry
   name :- schema/Str]
  (match-name? ace name))

;; ACL creation

(schema/defn add-name :- ACL
  "Add a new host ACE to this acl"
  ([type :- AuthType
    pattern :- schema/Str]
    (add-name empty-acl type pattern))
  ([acl :- ACL
    type :- AuthType
    pattern :- schema/Str]
    (conj acl (new-domain type pattern))))

(schema/defn allow :- ACL
  "Allow a new pattern to an ACL"
  ([pattern :- schema/Str]
    (add-name :allow pattern))
  ([acl :- ACL
   pattern :- schema/Str]
    (add-name acl :allow pattern)))

(schema/defn deny :- ACL
  "Deny a new pattern to an ACL"
  ([pattern :- schema/Str]
    (add-name :deny pattern))
  ([acl :- ACL
    pattern :- schema/Str]
    (add-name acl :deny pattern)))

;; ACL result

(schema/defn allowed? :- schema/Bool
  "Returns true if the name is allowed by acl, otherwise returns false"
  ([acl :- ACL
    name :- schema/Str]
    (allowed? acl name []))
  ([acl :- ACL
   name :- schema/Str
   captures :- [schema/Str]]
  (let [interpolated-acl (map #(interpolate-backreference % captures) acl)
        match (some #(if (match? % name) % false) interpolated-acl)]
      (if match
        (allow? match)
        false))))
