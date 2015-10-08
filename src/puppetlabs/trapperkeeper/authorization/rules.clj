(ns puppetlabs.trapperkeeper.authorization.rules
  (:require [schema.core :as schema]
            [clojure.tools.logging :as log]
            [clojure.string :as str]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.report :as report]
            [puppetlabs.trapperkeeper.authorization.ring :as ring])
(:import java.util.regex.Pattern))

;; Schemas

(def Type (schema/enum :path :regex))
(def Method (schema/enum :get :post :put :delete :head :any))
(def Methods (schema/either Method [Method]))

(def Rule
  {:type Type
   :path Pattern
   :method Methods
   :acl acl/ACL
   :sort-order schema/Int
   :name schema/Str
   (schema/optional-key :allow-unauthenticated) schema/Bool
   (schema/optional-key :query-params) {schema/Keyword #{schema/Str}}
   (schema/optional-key :file) schema/Str
   (schema/optional-key :line) schema/Int})

(def Rules
  "A list of rules"
  [Rule])

(def RuleMatch
  "A match? result"
  (schema/maybe {:rule Rule :matches [schema/Str]}))

(def MatchReport
  "A match result containing a match report"
  {:report report/Report :result schema/Bool (schema/optional-key :match-result) RuleMatch})

(def AuthorizationResult
  "A result returned by rules/allowed? that can be either authorized or non-authorized. If non-authorized it also
  contains an explanation message"
  { :authorized schema/Bool :message schema/Str :match-report report/Report})

;; Rule creation

(defn- unmangle-path
  [path]
  (-> path
      (str/replace "\\Q" "")
      (str/replace "\\E" "")
      (str/replace #"^\^" "")))

(schema/defn new-rule :- Rule
  "Creates a new rule with an empty ACL"
  [type :- Type
   path :- schema/Str
   method :- Methods
   sort-order :- schema/Int
   name :- schema/Str]
   {:type type
    :path (condp = type
            :path (re-pattern (str "^" (Pattern/quote path)))
            :regex (re-pattern path))
    :acl acl/empty-acl
    :method method
    :sort-order sort-order
    :name name})

(schema/defn tag-rule :- Rule
  "Tag a rule with a file/line - useful for instance when the rule has been read
  from an authorization file."
  [rule :- Rule
   file :- schema/Str
   line :- schema/Int]
  (-> rule
      (assoc :file file)
      (assoc :line line)))

(schema/defn query-param :- Rule
  "Add a query parameter matching value(s) to a rule. New values will be
   appended to existing values.

   The query parameters are in a map under the `:query-params` section of the
   rule. Keys in the map are keywords corresponding to the query parameters to
   match, and the values are sets of strings of acceptable values."
  [rule :- Rule
   param :- schema/Keyword
   value :- (schema/either schema/Str [schema/Str])]
  (update-in rule [:query-params param] (comp set into) (flatten [value])))

;; Rule ACL creation

(schema/defn allow :- Rule
  [rule :- Rule
   pattern :- schema/Str]
  (assoc rule :acl (acl/allow (:acl rule) pattern)))

(schema/defn allow-ip :- Rule
  [rule :- Rule
   pattern :- schema/Str]
  (assoc rule :acl (acl/allow-ip (:acl rule) pattern)))

(schema/defn deny :- Rule
  [rule :- Rule
   pattern :- schema/Str]
  (assoc rule :acl (acl/deny (:acl rule) pattern)))

(schema/defn deny-ip :- Rule
  [rule :- Rule
   pattern :- schema/Str]
  (assoc rule :acl (acl/deny-ip (:acl rule) pattern)))

;; Rule matching

(defn- re-find*
  "Like re-find, but always returns either nil or a vector of groups."
  [re s]
  (let [res (re-find re s)]
    (if (string? res) [res] res)))

(schema/defn method-match?
  "Return true if the provided method is equal to the value of `specified`. If
  `specified` is a list of methods, return true if `method` is contained in
  `specified`. If `specified` is set to :any then all methods will result in
  true."
  [method :- schema/Keyword
   specified :- Methods]
  (let [rules-list (if (keyword? specified) [specified] specified)]
    (or (some (partial = method) rules-list)
        (= specified :any))))

(defn- query-params-match?
  "Return true if query params match or if rule-params is nil."
  [request-params rule-params]
  (every? some?
          (for [k (keys rule-params)]
            (some (get rule-params k)
                  (flatten [(get request-params (name k))])))))

(schema/defn match? :- RuleMatch
  "Returns the rule if it matches the request URI, and also
   any capture groups of the Rule pattern if there are any."
  [rule :- Rule
   request :- ring/Request]
  (if (and (method-match? (:request-method request) (:method rule))
           (query-params-match? (:query-params request) (:query-params rule)))
    (if-let [matches (re-find* (:path rule) (:uri request))] ;; check rule against request uri
      {:rule rule :matches (into [] (rest matches))})))

(defn- request->description
  [request name rule]
  (let [ip (:remote-addr request)
        path (:uri request)
        method (:request-method request)
        authentic? (true? (ring/authorized-authentic? request))]
    (str "Forbidden request: " (if name (format "%s(%s)" name ip) ip)
         " access to " path " (method " method ")"
         (if-let [file (:file rule)] (str " at " file ":" (:line rule)))
         (format " (authentic: %s) " authentic?)
         (format "denied by rule '%s'." (:name rule)))))

(schema/defn sort-rules :- Rules
  "Sorts the rules based on their :sort-order, and then their :name if they
   have the same sort order value."
  [rules :- Rules]
  (sort-by (juxt :sort-order :name) rules))

(schema/defn deny-request :- AuthorizationResult
  "Logs the reason message at ERROR level and
   returns an unauthorized authorization result."
  [reason :- schema/Str
   report :- report/Report]
  (log/error reason)
  {:authorized false
   :message reason
   :match-report report})

;; Rules creation

(def empty-rules [])

(schema/defn add-rule
  [rules :- Rules
   rule :- Rule]
  (conj rules rule))

;; Rules check

(defn method->string
  "Transform a method as a keyword or a vector of keywords to a human-readable string"
  [m]
  (str/join "," (map #(-> % name str/upper-case) (flatten (vector m)))))

(schema/defn rule->name :- schema/Str
  "Returns a rule unique identifier"
  [rule :- Rule]
  (str (method->string (:method rule)) " " (unmangle-path (:path rule))))

(schema/defn new-rule-match :- report/RuleReport
  ([rule :- Rule
    result :- report/Match]
    (new-rule-match rule result []))
  ([rule :- Rule
    result :- report/Match
    acl-report :- report/ACLReport]
    { :rule (rule->name rule) :match result :acl-match acl-report }))

(schema/defn allow-rules? :- { :match schema/Bool (schema/optional-key :allowed) schema/Bool (schema/optional-key :reason) schema/Str :report report/Report (schema/optional-key :match-result) RuleMatch }
  "Find a matching rule in the given rules, and if one is found return if it is allowed or not.
  At the same time, fill a Report with all the match results."
  [rules :- Rules
   request :- ring/Request
   name :- schema/Str
   report :- report/Report]
  (letfn [
          ; rule matched, and possibly an ace matched
          (positive-match [v r match-result] (if (true? (:allow-unauthenticated r))
                                               (assoc v :match true :allowed true :report (report/append-rule-report (new-rule-match r :allow-unauthenticated) report) :reason "allow-unauthenticated is true - allowed")
                                               (let [report (:report v)
                                                     ip (:remote-addr request)
                                                     acl (:acl (:rule match-result))
                                                     matches (:matches match-result)
                                                     common-result {:match true :reason "" :match-result match-result}
                                                     ]
                                                 (if-let [{allowed :result rule-report :report} (and (true? (ring/authorized-authentic? request)) ; authenticated?
                                                                                                     (acl/allowed? acl name ip matches))]
                                                   (merge v
                                                          common-result
                                                          {:allowed allowed :report (report/append-rule-report (new-rule-match r :yes rule-report) report)})
                                                   (merge v
                                                          common-result
                                                          {:allowed false :report (report/append-rule-report (new-rule-match r :yes) report)})))))


          ; this rule doesn't match
          (no-match [v r] (assoc v :report (report/append-rule-report (new-rule-match r :no) (:report v))))

          ; this rule is skipped (previous match occured)
          (skipped [v r] (assoc v :report (report/append-rule-report (new-rule-match r :skipped) (:report v))))

          ; the core of the logic: while we don't have a match, try to match the current rule, but after a
          ; given match, skip all following rules, marking them as skipped
          (rule-match [v r] (if (not (:match v))
                              (if-let [match-result (match? r request)]
                                (positive-match v r match-result)
                                (no-match v r))
                              (skipped v r)))]
    (reduce rule-match {:report report :match false } rules)))

(schema/defn allowed? :- AuthorizationResult
  "Checks if a request is allowed access given the list of rules. Rules
   will be checked in the given order; use `sort-rules` to first sort them."
  [rules :- Rules
   request :- ring/Request
   name :- schema/Str]

  (let [report (report/new-report request name)
        {match :match report :report allowed :allowed match-result :match-result reason :reason} (allow-rules? rules request name report)]
    (if match
      (if allowed
        {:authorized true :message reason :match-report report}
        (deny-request (request->description request name (:rule match-result)) report))
    (deny-request "global deny all - no rules matched" report))))

(schema/defn authorized? :- schema/Bool
  [result :- AuthorizationResult]
  (:authorized result))
