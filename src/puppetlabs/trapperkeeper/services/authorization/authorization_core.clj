(ns puppetlabs.trapperkeeper.services.authorization.authorization-core
  (:require [clojure.string :as str]
            [puppetlabs.kitchensink.core :as ks]
            [schema.core :as schema]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.acl :as acl])
  (:import (java.util.regex PatternSyntaxException)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Constants

(def required-keys
  "Keys required in an auth rule map."
  [:path :type])

(def required-or-key
  "At least one of these keys is required in an auth rule map."
  #{:deny :allow :allow-unauthenticated})

(def acl-func-map
  "This is a function map to allow a programmatic execution of allow/deny directives"
  {:allow #(rules/allow %1 %2)
   :deny #(rules/deny %1 %2)})

(def new-rule-func-map
  "This is a function map to allow programmatic execution of path/regex rules"
  {:path rules/new-path-rule :regex rules/new-regex-rule})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Private

(defn pprint-rule
  [rule]
  (str/trim (ks/pprint-to-string rule)))

(defn- method
  "Returns the method key of a given config map, or :any if none"
  [config-map]
  (keyword (get-in config-map [:match-request :method] :any)))

(defn- build-rule
  "Build a new Rule based on the provided config-map"
  [config-map]
  (let [rule-type (keyword (get-in config-map [:match-request :type] :path))
        path (get-in config-map [:match-request :path])
        rule-fn (rule-type new-rule-func-map)
        rule (rule-fn path (method config-map))]
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
                 (pprint-rule (:path (:match-request rule))) " is invalid. "
                 "It should be a string."))))
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
      (when-not (string? param)
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
  config)

(schema/defn transform-config :- rules/Rules
  "Transforms the authorization service config into a list of Rules that work
  with the authorization code."
  [config]
  (map config->rule config))
