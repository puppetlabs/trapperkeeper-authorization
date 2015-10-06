(ns puppetlabs.trapperkeeper.authorization.rules
  (:require [clojure.tools.logging :as log]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [schema.core :as schema])
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

(def AuthorizationResult
  "A result returned by rules/allowed? that can be either authorized or non-authorized. If non-authorized it also
  contains an explanation message"
  { :authorized schema/Bool :message schema/Str })

;; Rule creation

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
  [reason :- schema/Str]
  (log/error reason)
  {:authorized false
   :message reason})

;; Rules creation

(def empty-rules [])

(schema/defn add-rule
  [rules :- Rules
   rule :- Rule]
  (conj rules rule))

;; Rules check

(schema/defn allowed? :- AuthorizationResult
  "Checks if a request is allowed access given the list of rules. Rules
   will be checked in the given order; use `sort-rules` to first sort them."
  [rules :- Rules
   request :- ring/Request
   name :- schema/Str]
  (if-let [{:keys [rule matches]} (some #(match? % request) rules)]
    (if (true? (:allow-unauthenticated rule))
      {:authorized true :message "allow-unauthenticated is true - allowed"}
      (if (and (true? (ring/authorized-authentic? request)) ; authenticated?
            (acl/allowed? (:acl rule) name matches))
        {:authorized true :message ""}
        (deny-request (request->description request name rule))))
    (deny-request "global deny all - no rules matched")))

(schema/defn authorized? :- schema/Bool
  [result :- AuthorizationResult]
  (:authorized result))
