(ns puppetlabs.trapperkeeper.authorization.rules
  (:require [schema.core :as schema]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.ring :refer [Request]])
  (:import java.util.regex.Pattern))

;; Schemas

(def Type (schema/enum :string :regex))
(def Method (schema/enum :get :post :put :delete :head :any))

(def Rule
  "An ACL rule, with no less than a matching path, possibly a method list and an acl"
  {
   :type (schema/enum :string :regex)
   :path Pattern
   :method (schema/enum :get :post :put :delete :head :any)
   :acl acl/ACL
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

(schema/defn equals-rule :- schema/Bool
  "Test if two given rule are fully equal"
  [a :- Rule b :- Rule]
  (and
    (= (:type a) (:type b))
    (= (:acl a) (:acl b))
    (= (:method a) (:method b))
    (= (str (:path a)) (str (:path b)))))

(schema/defn tag-rule :- Rule
  "Tag a rule with a file/line - useful for instance when the rule has been read
  from an authorization file."
  [rule :- Rule
   file :- schema/Str
   line :- schema/Int]
  (-> rule
      (assoc :file file)
      (assoc :line line)))

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

(schema/defn match? :- RuleMatch
  "returns the rule if it matches the request URI, and also any capture groups of the Rule pattern if there are."
  [rule :- Rule
   request :- Request]
  (if (method-match? (:request-method request) (:method rule)) ;; make sure method match
    (if-let [matches (re-find* (:path rule) (:uri request))] ;; check rule against request uri
      {:rule rule :matches (into [] (rest matches))})))

(defn- request->description
  [request name rule]
  (let [ip (:remote-addr request)
        path (:uri request)
        method (:request-method request)]
    (str "Forbidden request: " (if name
          (format "%s(%s)" name ip)
          ip) " access to " path " (method " method ")"
         (if-let [ file (:file rule) ]
           (str " at " file ":" (:line rule))
           ""))))

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
   request :- Request
   name :- schema/Str]
  (if-let [ { matched-rule :rule matches :matches } (some #(match? % request) rules)]
    (if (acl/allowed? (:acl matched-rule) name (:remote-addr request) matches)
      {:authorized true :message ""}
      {:authorized false :message (request->description request name matched-rule)})
    {:authorized false :message "global deny all - no rules matched"}))

(schema/defn authorized? :- schema/Bool
  [result :- AuthorizationResult]
  (:authorized result))

(schema/defn equals-rules :- schema/Bool
  "Test if two rule sets are equals"
  [a :- Rules b :- Rules]
  (and (= (count a) (count b))
       (every? #(equals-rule (first %) (second %)) (map vector a b))))
