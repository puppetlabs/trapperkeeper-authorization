(ns puppetlabs.trapperkeeper.services.authorization.authorization-core
  (:require [clojure.string :as str]
            [clojure.tools.logging :as log]
            [puppetlabs.kitchensink.core :as ks]
            [schema.core :as schema]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.acl :as acl])
  (:import (java.util.regex PatternSyntaxException)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Constants

(def valid-methods
  "HTTP methods which are allowed to be configured in a rule."
  #{"get" "post" "put" "delete" "head"})

(def acl-func-map
  "This is a function map to allow a programmatic execution of allow/deny directives"
  {:allow #(rules/allow %1 %2)
   :deny #(rules/deny %1 %2)})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Private

(defn pprint-rule
  [rule]
  (str/trim (ks/pprint-to-string rule)))

(defn- method
  "Returns the method key of a given config map, or :any if none"
  [config-map]
  (let [method-from-config (get-in config-map [:match-request :method] "any")
        config-method->rule-method (comp keyword str/lower-case)]
    (if (vector? method-from-config)
      (mapv config-method->rule-method method-from-config)
      (config-method->rule-method method-from-config))))

(defn- build-rule
  "Build a new Rule based on the provided config-map"
  [config-map]
  (let [type (keyword (get-in config-map [:match-request :type] :path))
        path (get-in config-map [:match-request :path])
        method (method config-map)
        sort-order (:sort-order config-map)
        name (:name config-map)
        rule (rules/new-rule type path method sort-order name)]
    (if (true? (:allow-unauthenticated config-map))
      (assoc rule :allow-unauthenticated true)
      rule)))

(defn- add-individual-acl
  "Add an individual acl to a given rule:
    (add-individual-acl :allow \"*.domain.org\" rule)
  "
  [acl-type value rule]
  (let [v (vec (flatten [value]))]
    (reduce #((get acl-func-map acl-type) %1 %2) rule v)))

(defn add-acl
  "Add various ACL to the incoming rule, based on content of the config-map"
  [rule config-map]
  (->> (select-keys config-map #{:allow :allow-ip :deny :deny-ip})
       (reduce #(add-individual-acl (first %2) (second %2) %1) rule)))

(defn add-query-params
  "Add any query parameters specified in configuration to the rule."
  [rule {{:keys [query-params]} :match-request}]
  (reduce-kv rules/query-param rule query-params))

(schema/defn config->rule :- rules/Rule
  "Given a rule expressed as a map in the configuration return a Rule suitable
   for use in a list with the allowed? function.

   This assumes the configuration has been validated via
   `validate-auth-config-rule!`."
  [m]
  (-> (build-rule m)
      (add-acl m)
      (add-query-params m)))

(defn valid-method?
  "Returns true if the given rule contains either a valid method, or no speicfied
  method."
  [rule]
  (let [rule-method (get-in rule [:match-request :method])
        method (if (string? rule-method) [rule-method] rule-method)]
    (cond
      (nil? rule-method)
      true

      (vector? method)
      (every? valid-methods (map str/lower-case method))

      :else
      false)))

(defn validate-auth-config-rule!
  "Tests to see if the given map contains the proper data to define an auth
  rule. Returns the provided rule if successful, otherwise throws an exception
  with a useful error message."
  [rule]
  (when-not (map? rule)
    (throw (IllegalArgumentException.
            "An authorization rule should be specified as a map.")))
  (when-not (:match-request rule)
    (throw (IllegalArgumentException.
            "An authorization rule must contain a 'match-request' section.")))
  (doseq [k [:path :type]]
    (when-not (contains? (:match-request rule) k)
      (throw (IllegalArgumentException.
              (str "The authorization rule specified as " (pprint-rule rule)
                   " does not contain a '" (name k) "' key.")))))
  (doseq [k [:sort-order :name]]
    (when-not (get rule k)
      (throw (IllegalArgumentException.
              (str "The authorization rule specified as " (pprint-rule rule)
                   " does not contain a '" (name k) "' key.")))))
  (when (or (not (integer? (:sort-order rule)))
            (< (:sort-order rule) 1)
            (> (:sort-order rule) 999))
    (throw (IllegalArgumentException.
            (str "The sort-order set in the authorization rule specified as "
                 (pprint-rule rule) " is invalid. It should be a number "
                 "from 1 to 999."))))
  (if (:allow-unauthenticated rule)
    (if (some #{:deny :allow} (keys rule))
      (throw (IllegalArgumentException.
               (str "Authorization rule specified as  " (pprint-rule rule)
                 " cannot have allow or deny if allow-unauthenticated."))))
    (when-not (some #{:deny :allow} (keys rule))
      (throw (IllegalArgumentException.
               (str "Authorization rule specified as " (pprint-rule rule)
                 " must contain either a 'deny' or 'allow' rule.")))))
  (when-not (string? (:type (:match-request rule)))
    (throw (IllegalArgumentException.
            (str "The type set in the authorization rule specified "
                 "as " (pprint-rule rule) " should be a "
                 "string that is either 'path' or 'regex'."))))
  (let [type (-> rule :match-request :type name str/lower-case)]
    (when-not (or (= type "path") (= type "regex"))
      (throw (IllegalArgumentException.
              (str "The type set in the authorization rule specified "
                   "as " (pprint-rule rule) " is invalid. "
                   "It should be set to either 'path' or 'regex'.")))))
  (when-not (string? (:path (:match-request rule)))
    (throw (IllegalArgumentException.
            (str "The path set in the authorization rule specified as "
                 (pprint-rule rule) " is invalid. "
                 "It should be a string."))))
  (when-not (valid-method? rule)
    (throw (IllegalArgumentException.
             (str "The method specified in the authorization rule specified as "
                  (pprint-rule rule) " is invalid. "
                  "It should be either a string or list of strings that is equal "
                  "to one of the following methods: '"
                  (str/join "', '" (sort valid-methods)) "'"))))
  (when (= "regex" (-> rule :match-request :type name str/lower-case))
    (try
      (re-pattern (:path (:match-request rule)))
      (catch PatternSyntaxException e
        (throw (IllegalArgumentException.
                (str "The path regex provided in the rule defined as "
                     (pprint-rule rule) " is invalid: "
                     (.getMessage e)))))))
  (doseq [[type names] (select-keys rule [:allow :deny])]
    (if (vector? names)
      (when-not (every? string? names)
        (throw (IllegalArgumentException.
                (str "The " (name type) " list in the rule specified as "
                     (pprint-rule rule)
                     " contains one or more names that are not strings."))))
      (when-not (string? names)
        (throw (IllegalArgumentException.
                (str "The name '" names "' in the '" (name type) "' field of "
                     "the rule specified as " (pprint-rule rule) " is invalid. "
                     "It should be a string."))))))
  (when-let [query-params (:query-params (:match-request rule))]
    (when-not (map? query-params)
      (throw (IllegalArgumentException. "Rule query-params must be a map.")))
    (doseq [param (keys query-params)
            :let [value (get query-params param)]]
      (when-not (keyword? param)
        (throw (IllegalArgumentException.
                (str "The query-param '" param "' in the rule specified as "
                     (pprint-rule rule) " is invalid. It should be a string."))))
      (when-not (or (string? value)
                    (vector? value))
        (throw (IllegalArgumentException.
                (str "The query-param value for '" param "' in the rule "
                     "specified as " (pprint-rule rule) " is invalid. "
                     "It should be a string or list of strings."))))
      (when (vector? value)
        (when-not (every? string? value)
          (throw (IllegalArgumentException.
                  (str "The '" param "' query-param in the rule specified as "
                       (pprint-rule rule) " contains one or more values that "
                       "are not strings.")))))))
  rule)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn validate-auth-config!
  "Validates the given authorization service configuration. If an invalid
  configuration is found an IllegalArgumentException will be thrown, otherwise
  the input config will be returned."
  [config]
  (when-not (vector? config)
    (throw (IllegalArgumentException.
            "The provided authorization service config is not a list.")))
  (doseq [rule config]
    (validate-auth-config-rule! rule))
  (doseq [[name rules] (group-by :name config)]
    (when-not (= 1 (count rules))
      (throw (IllegalArgumentException.
              (str "Duplicate rules named '" name "'. "
                   "Rules must be uniquely named.")))))
  config)

(schema/defn transform-config :- rules/Rules
  "Transforms the (validated) authorization service config into a list of Rules
   that work with the authorization code. Assumes config has been validated via
   `validate-auth-config!`. A warning is logged if the rules in the config are
   not in ascending sort order."
  [config]
  (let [sorted (rules/sort-rules (map config->rule config))
        trim-fn #(select-keys % [:sort-order :name])]
    (when-let [mismatch (some #(when-not (= (first %) (second %)) %)
                              (partition 2 (interleave (map trim-fn config)
                                                       (map trim-fn sorted))))]
      (log/warnf (str "Found rule '%s' out of order; expected '%s'. Rules in "
                      "configuration file not in ascending sort order.")
                 (:name (first mismatch)) (:name (second mismatch))))
    sorted))
