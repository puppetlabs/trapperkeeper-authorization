(ns puppetlabs.trapperkeeper.authorization.acl
  (:require [schema.core :as schema]
            [clojure.string :as str]
            [puppetlabs.trapperkeeper.authorization.report :as report]
            [inet.data.ip :as ip]))

;; Schemas

(def auth-type (schema/enum :allow :deny))

(def Entry
  "An authorization entry matching a network or a domain"
  {:auth-type auth-type
  :type (schema/enum :allow-all :ip :domain :opaque :regex :dynamic)
  :qualifier (schema/enum :exact :inexact)
  :length (schema/maybe schema/Int)
  :pattern schema/Any})

(def ACL
  "An ordered list of authorization Entry"
  #{Entry})

;; Rules description

(defn- unmunge-name
  "the reverse of munge-name"
  [name]
  (str/join "." (reverse name)))

(defn- pattern->string
  "Transform back a pattern into a human-readable form"
  [entry]
  (let [pattern (:pattern entry)
        type (:type entry)
        length (:length entry)]
    (condp = type
      :allow-all "*"
      :domain (unmunge-name (if-not length
                              pattern
                              (conj pattern "*")))
      :opaque (first pattern)
      :regex (str "/" pattern "/")
      :dynamic (unmunge-name pattern)
      :ip (str pattern))))

(schema/defn entry->string :- schema/Str
  "Converts an Entry to a human-readable string"
  [entry :- Entry]
  (let [auth-type (name (:auth-type entry))
        pattern (pattern->string entry)]
    (str auth-type " " pattern)))

(schema/defn acl->string :- [schema/Str]
  "Converts an acl to a human-readable form"
  [a :- ACL]
  (vec (map entry->string a)))

(schema/defn exact? :- schema/Bool
  [ace :- Entry]
  (= (ace :qualifier) :exact))

(schema/defn ip? :- schema/Bool
  [ace :- Entry]
  (= (ace :type) :ip))

(schema/defn deny? :- schema/Bool
  [ace :- Entry]
  (= (ace :auth-type) :deny))

(schema/defn allow-all? :- schema/Bool
  [ace :- Entry]
  (= (ace :type) :allow-all))

(schema/defn allow? :- schema/Bool
  [ace :- Entry]
  (or (= (ace :auth-type) :allow) (allow-all? ace)))

;; ACE comparison

(defmacro or-zero
  "This works exactly like the original clojure or macro except that 0
  is considered false like in ruby."
  ([] nil)
  ([x] x)
  ([x & next]
    `(let [or# ~x]
       (if (and (not= 0 or#) or#) or# (or-zero ~@next)))))

(schema/defn ace-compare :- schema/Int
  "Compare two ACE, with:
   * exact wins other inexact
   * ip wins other domain
   * larger pattern length wins
   * order patterns"
  [a :- Entry
   b :- Entry]
  (or-zero
    (compare (allow-all? b) (allow-all? a))
    (compare (exact? b) (exact? a))
    (compare (ip? b) (ip? a))
    (and (not= (a :length) (b :length)) (compare (b :length) (a :length)))
    (compare (deny? b) (deny? a))
    (if (ip? a)
      (compare (str (a :pattern)) (str (b :pattern)))
      (compare (a :pattern) (b :pattern)))))

(def empty-acl (sorted-set-by ace-compare))

;; ACE creation

(defn munge-name
  [pattern]
  (-> pattern (str/lower-case) (str/split #"\.") reverse vec))

(def allow-all { :auth-type :allow :type :allow-all :qualifier :exact :length nil :pattern [] })

(schema/defn new-domain :- Entry
  "Creates a new ACE for a domain"
  [type :- auth-type
   pattern :- schema/Str]
  (cond
    (and (= "*" pattern) (= type :allow))
    allow-all

    ; global deny
    (and (= "*" pattern) (= type :deny))
    {:auth-type :deny
     :type :regex
     :qualifier :exact
     :length nil
     :pattern #"^*$"}

    ; exact domain
    (re-matches #"^(\w[-\w]*\.)+[-\w]+$" pattern)
    {:auth-type type
     :type :domain
     :qualifier :exact
     :length nil
     :pattern (munge-name pattern)}

    ; *.domain.com
    (re-matches #"^\*(\.(\w[-\w]*)){1,}$" pattern)
    (let [host_sans_star (vec (drop-last (munge-name pattern)))]
      {:auth-type type
       :type :domain
       :qualifier :inexact
       :length (count host_sans_star)
       :pattern host_sans_star})

    ; backreference
    (re-find #"\$\d+" pattern)
    {:auth-type type
     :type :dynamic
     :qualifier :exact
     :length nil
     :pattern (munge-name pattern)}

    ; opaque string
    (re-matches #"^\w[-.@\w]*$" pattern)
    {:auth-type type
     :type :opaque
     :qualifier :exact
     :length nil
     :pattern [pattern]}

    ; regex
    (re-matches #"^/.*/$" pattern)
    {:auth-type type
     :type :regex
     :qualifier :inexact
     :length nil
     :pattern (str/replace pattern #"^/(.*)/$" "$1")}

    :else
    (throw (Exception. (str "invalid domain pattern: " pattern)))))

(schema/defn new-ip :- Entry
  "Creates a new ACE for an ip address or network"
  [type :- auth-type
   pattern :- schema/Str]
  (cond
    ; exact domain
    (re-matches #"^((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){1,3}\*$" pattern)
      (let [segments (-> pattern (str/split #"\.") drop-last)
            bits (* 8 (count segments))]
      {:auth-type type :type :ip :qualifier :inexact
       :length bits
       :pattern (ip/network (str (str/join "." (map str (take 4 (concat segments [0 0 0])))) "/" bits))})
    (ip/network? pattern) {:auth-type type :type :ip :qualifier :inexact :length (ip/network-length pattern) :pattern (ip/network pattern)}
    (ip/address? pattern) {:auth-type type :type :ip :qualifier :exact :length nil :pattern (ip/address pattern)}))

;; ACE matching

(schema/defn match-name? :- schema/Bool
  "Checks that name matches the given ace"
  [ace :- Entry
   name :- schema/Str]
  (if (= ace allow-all) ; always match
    true
    (if (= (ace :type) :regex)
      (boolean (re-find (re-pattern (ace :pattern)) name))
      (let [name (munge-name name)
            pattern (ace :pattern)
            exact (= (ace :qualifier) :exact)]
        (or (= pattern name) (and (not exact) (every? (fn [[a b]] (= a b)) (map vector pattern name))))))))

(defn- substitute-backreference
  "substiture $1, $2... by the same index in the captures vector"
  [in captures]
  (str/replace in #"\$(\d+)" #(nth captures (- (read-string (second %)) 1))))

(defn interpolate-backreference
  "change all possible backreferences in ace patterns to values from the capture groups"
  [ace captures]
  (if (= (ace :type) :dynamic)
    (new-domain (ace :auth-type) (str/join "." (map #(substitute-backreference % captures) (reverse (ace :pattern)))))
    ace))

(schema/defn match? :- schema/Bool
  "Returns true if either the given name or ip matches the given ace"
  [ace :- Entry
   name :- schema/Str
   ip :- schema/Str]
  (if (= (ace :type) :ip)
    (ip/network-contains? (ace :pattern) ip)
    (match-name? ace name)))

;; ACL creation

(schema/defn add-name :- ACL
  "Add a new host ACE to this acl"
  ([type :- auth-type
    pattern :- schema/Str]
    (add-name empty-acl type pattern))
  ([acl :- ACL
    type :- auth-type
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

(schema/defn add-ip :- ACL
  "Add a new ip ACE to an ACL"
  ([type :- auth-type
    pattern :- schema/Str]
    (add-ip empty-acl type pattern))
  ([acl :- ACL
    type :- auth-type
    pattern :- schema/Str]
    (conj acl (new-ip type pattern))))

(schema/defn allow-ip :- ACL
  "Allow a new ip to an ACL"
  ([pattern :- schema/Str]
    (add-ip :allow pattern))
  ([acl :- ACL
    pattern :- schema/Str]
    (add-ip acl :allow pattern)))

(schema/defn deny-ip :- ACL
  "Deny a new ip to an ACL"
  ([pattern :- schema/Str]
    (add-ip :deny pattern))
  ([acl :- ACL
    pattern :- schema/Str]
    (add-ip acl :deny pattern)))

;; ACL result

(schema/defn new-entry-report :- report/EntryReport
  "Creates a new EntryReport for a given match"
  [ace :- Entry
   match :- schema/Bool]
  {:pattern (pattern->string ace) :type (:auth-type ace) :match (if match :yes :no)})

(schema/defn new-skipped-entry-report :- report/EntryReport
  "Creates a new EntryReport for a given match"
  [ace :- Entry]
  {:pattern (pattern->string ace) :type (:auth-type ace) :match :skipped})

(schema/defn find-ace-match :- { :match schema/Bool :report report/EntryReport }
  "Find if the given Entry matches. If it matches return true for the :result
  At the same time accumulate information in the report"
  [ace :- Entry
   name :- schema/Str
   ip :- schema/Str]
  (let [match (match? ace name ip)]
    {:match match :report (new-entry-report ace match)}))

(schema/defn find-acl-match :- {:match schema/Bool :entry Entry :report report/ACLReport}
  "Scan all interpolated acl to find one that matches. If one matches then return true as :result
  At the same time accumulate information in the report "
  [acl :- [Entry]
   name :- schema/Str
   ip :- schema/Str]
  (let [report (report/new-acl-report)
        initial-result {:match false :report report}]
    (letfn [(match-and-report [v entry] (if (not (:match v))
                                          (let [{m :match r :report} (find-ace-match entry name ip)]
                                            {:match m :entry entry :report (report/append-acl-report (:report v) r)})
                                          (assoc v :report (report/append-acl-report (:report v) (new-skipped-entry-report entry)))))]
      (reduce match-and-report initial-result acl))))

(schema/defn allowed? :- {:result schema/Bool :report report/ACLReport}
  "Returns true if either name or ip are allowed by acl, otherwise returns false"
  ([acl :- ACL
    name :- schema/Str
    ip :- schema/Str]
    (allowed? acl name ip []))
  ([acl :- ACL
   name :- schema/Str
   ip :- schema/Str
   captures :- [schema/Str]]
  (let [interpolated-acl (map #(interpolate-backreference % captures) acl)
        { match :match entry :entry report :report } (find-acl-match interpolated-acl name ip)]
      (if match
        {:result (allow? entry) :report report}
        {:result false :report report}))))
