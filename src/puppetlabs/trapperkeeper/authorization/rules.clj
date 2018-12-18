(ns puppetlabs.trapperkeeper.authorization.rules
  (:require [clojure.tools.logging :as log]
            [puppetlabs.i18n.core :refer [trs tru]]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [schema.core :as schema])
  (:import clojure.lang.IFn
           java.util.regex.Pattern))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schemas

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

(def RuleMatch
  "A `match?` result containing the matched rule and any regex capture groups."
  {:rule Rule :matches [schema/Str]})

(def AuthorizationResult
  "The result of a `rules/allowed?` indicating whether the request should be
   authorized or not, and an explanation message if it's not. Also contains
   meta-information like the request in question."
  {:authorized schema/Bool
   :message schema/Str
   :request ring/Request})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Rule creation

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

(schema/defn ^:always-validate allow :- Rule
  [rule :- Rule
   pattern :- acl/ACEConfig]
  (assoc rule :acl (acl/allow (:acl rule) pattern)))

(schema/defn ^:always-validate deny :- Rule
  [rule :- Rule
   pattern :- acl/ACEConfig]
  (assoc rule :acl (acl/deny (:acl rule) pattern)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Rule matching

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

(schema/defn sort-rules :- [Rule]
  "Sorts the rules based on their :sort-order, and then their :name if they
   have the same sort order value."
  [rules :- [Rule]]
  (sort-by (juxt :sort-order :name) rules))

(schema/defn requestor :- schema/Str
  "Returns a string that identifies the source of the request containing
   at least the IP address and the hostname if available."
  [request :- ring/Request]
  (let [ip (:remote-addr request)
        name (ring/authorized-name request)]
    (if (empty? name)
      (str ip)
      (format "%s(%s)" name ip))))

(schema/defn match? :- (schema/maybe RuleMatch)
  "Returns the rule if it matches the request URI, and also
   any capture groups of the Rule pattern if there are any."
  [rule :- Rule
   request :- ring/Request]
  (if (and (method-match? (:request-method request) (:method rule))
           (query-params-match? (:query-params request) (:query-params rule)))
    (if-let [matches (re-find* (:path rule) (:uri request))]
      {:rule rule :matches (into [] (rest matches))}
      (log/trace
       (trs "Request to ''{0}'' from ''{1}'' did not match rule ''{2}'' - continuing matching"
            (:uri request) (requestor request) (:name rule))))))

(defn- request->log-description
  [request rule]
  (let [from (requestor request)
        path (:uri request)
        method (:request-method request)
        authenticated? (true? (ring/authorized-authenticated request))]
    (if-let [file (:file rule)]
      (trs "Forbidden request: {0} access to {1} (method {2}) at {3}:{4} (authenticated: {5}) denied by rule ''{6}''."
           from path method file (:line rule) authenticated? (:name rule))
      (trs "Forbidden request: {0} access to {1} (method {2}) (authenticated: {3}) denied by rule ''{4}''."
           from path method authenticated? (:name rule)))))

(defn- request->resp-description
  [request rule]
  (let [path (:uri request)
        method (:request-method request)]
    (tru "Forbidden request: {0} (method {1}). Please see the server logs for details."
         path method)))

(schema/defn allow-request :- AuthorizationResult
  "Logs debugging information about the request and rule at the TRACE level
   and returns an authorized authorization result with the provided message."
  [request :- ring/Request
   rule :- Rule
   message :- schema/Str]
  (log/trace
   (trs "Request to ''{0}'' from ''{1}'' handled by rule ''{2}'' - request allowed"
        (:uri request) (requestor request) (:name rule)))
  {:authorized true
   :message message
   :request request})

(schema/defn deny-request :- AuthorizationResult
  "Logs debugging information about the request and rule at the TRACE level
   as well as the reason for denial at the ERROR level, and returns an
   unauthorized authorization result with the provided reason message."
  ([request
    rule
    reason]
   (deny-request request rule reason reason))
  ([request :- ring/Request
    rule :- (schema/maybe Rule)
    log-reason :- schema/Str
    resp-reason :- schema/Str]
   (if rule
     (log/trace
      (trs "Request to ''{0}'' from ''{1}'' handled by rule ''{2}'' - request denied"
           (:uri request) (requestor request) (:name rule)))
     (log/trace
      (trs "Request to ''{0}'' from ''{1}'' did not match any rules - request denied"
           (:uri request) (requestor request))))
   (log/error log-reason)
   {:authorized false
    :message resp-reason
    :request request}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Rules checking

(schema/defn allowed? :- AuthorizationResult
  "Checks if a request is allowed access given the list of rules. Rules
   will be checked in the given order; use `sort-rules` to first sort them."
  [request :- ring/Request
   rules :- [Rule]
   oid-map :- acl/OIDMap
   rbac-is-permitted? :- (schema/maybe IFn)]
  (if-let [{:keys [rule matches]} (some #(match? % request) rules)]
    (if (true? (:allow-unauthenticated rule))
      (allow-request request rule "allow-unauthenticated is true - allowed")
      (if (or (and (true? (ring/authorized-authenticated request))
                   (acl/allowed? (:acl rule)
                                 {:certname (ring/authorized-name request)
                                  :extensions (ring/authorized-extensions request)}
                                 {:oid-map oid-map
                                  :captures matches}))
              (acl/rbac-allowed? (:acl rule) (:rbac-subject request) rbac-is-permitted?))
        (allow-request request rule "")
        (deny-request request rule (request->log-description request rule)
                      (request->resp-description request rule))))
    (deny-request request nil "global deny all - no rules matched")))

(schema/defn authorized? :- schema/Bool
  [result :- AuthorizationResult]
  (:authorized result))
