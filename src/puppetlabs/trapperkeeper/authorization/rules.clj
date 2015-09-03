(ns puppetlabs.trapperkeeper.authorization.rules
  (:require [schema.core :as schema]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.ring :as ring])
  (:import java.util.regex.Pattern))

;; Schemas

(def Type (schema/enum :string :regex))
(def Method (schema/enum :get :post :put :delete :head :any))

(def Rule
  "An ACL rule, with no less than a matching path, possibly a method list and an acl"
  {
   :type Type
   :path Pattern
   :method Method
   (schema/optional-key :allow-unauthenticated) schema/Bool
   :acl acl/ACL
   (schema/optional-key :query-params) {schema/Str #{schema/Str}}
   (schema/optional-key :file) schema/Str
   (schema/optional-key :line) schema/Int
   })

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
  ([type :- Type
    pattern :- Pattern]
    {:type type :path pattern :acl acl/empty-acl :method :any})
  ([type :- Type
    pattern :- Pattern
    method :- Method]
    {:type type :path pattern :acl acl/empty-acl :method method}))

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
   rule. Keys in the map are strings corresponding to the query parameters to
   match, and the values are sets of strings of acceptable values."
  [rule :- Rule
   param :- schema/Str
   value :- (schema/either schema/Str [schema/Str])]
  (update-in rule [:query-params param] (comp set into) (flatten [value])))

(defn- path->pattern
  "Returns a valid regex from a path"
  [path]
  (re-pattern (str "^" (Pattern/quote path))))

(schema/defn new-path-rule :- Rule
  "Creates a new rule from a path-info with an empty ACL"
  ([path :- schema/Str]
    (new-path-rule path :any))
  ([path :- schema/Str
    method :- Method]
    (new-rule :string (path->pattern path) method)))

(schema/defn new-regex-rule :- Rule
  "Creates a new rule from a regex (as a string) with an empty ACL"
  ([regex :- schema/Str]
    (new-regex-rule regex :any))
  ([regex :- schema/Str method :- Method]
    (new-rule :regex (re-pattern regex) method)))

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

(defn- method-match?
  "Return true if both mathod a and b match or if one is :any"
  [a b]
  (or (= a b) (some #{:any} [a b])))

(defn- query-params-match?
  "Return true if query params match or if rule-params is nil."
  [request-params rule-params]
  (every? some?
          (for [k (keys rule-params)]
            (some (get rule-params k)
                  (flatten [(get request-params k)])))))

(schema/defn match? :- RuleMatch
  "Returns the rule if it matches the request URI, and also any capture groups of the Rule pattern if there are."
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
        authentic? (true? (get-in request ring/is-authentic-key))]
    (str "Forbidden request: " (if name
          (format "%s(%s)" name ip)
          ip) " access to " path " (method " method ")"
         (if-let [ file (:file rule) ]
           (str " at " file ":" (:line rule)))
         (format " (authentic: %s)" authentic?))))

;; Rules creation

(def empty-rules [])

(schema/defn add-rule
  [rules :- Rules
   rule :- Rule]
  (conj rules rule))

;; Rules check

(schema/defn allowed? :- AuthorizationResult
  "Returns an AuthorizationResult of the given Rule set."
  [rules :- Rules
   request :- ring/Request
   name :- schema/Str]
  (if-let [ { matched-rule :rule matches :matches } (some #(match? % request) rules)]
    (if (true? (:allow-unauthenticated matched-rule))
      {:authorized true :message "allow-unauthenticated is true - allowed"}
      (if (and (true? (get-in request ring/is-authentic-key)) ; authenticated?
            (acl/allowed? (:acl matched-rule) name (:remote-addr request) matches))
        {:authorized true :message ""}
        {:authorized false :message (request->description request name matched-rule)}))
    {:authorized false :message "global deny all - no rules matched"}))

(schema/defn authorized? :- schema/Bool
  [result :- AuthorizationResult]
  (:authorized result))
