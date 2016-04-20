(ns puppetlabs.trapperkeeper.services.authorization.authorization-core
  (:require [clojure.string :as str]
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
  "A function map to allow a programmatic execution of allow/deny directives"
  {:allow rules/allow
   :deny rules/deny})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Private

(defn ^:private reject! [& strings]
  (throw (IllegalArgumentException. (apply str strings))))

(schema/defn validate-ace-config-map!
  [config-value :- (schema/pred map? "map?")]
  (when (:extensions config-value)
    (when-not (nil? (schema/check acl/ExtensionRule (:extensions config-value)))
      (reject! "extensions key should map an extension to a value or list of values; got "
               (:extensions config-value))))

  (when (:certname config-value)
    (when-not (nil? (schema/check schema/Str (:certname config-value)))
      (reject! (format "certname key should map to a string; got '%s'" (:certname config-value)))))

  (when (or (not (or (:extensions config-value) (:certname config-value)))
            (and (:extensions config-value) (:certname config-value)))
    (reject! "ACL Definition must contain exactly one of 'certname' or 'extensions' keys;"
             (format " got '%s'" config-value))))

(schema/defn canonicalize-acl :- acl/ACEConfig
  [config-value]
  (cond
    (string? config-value) {:certname config-value}
    (map? config-value) (do (validate-ace-config-map! config-value)
                            config-value)
    :else (reject! (format "Unable to parse ACL; expected string or map but got: '%s'"
                           config-value))))

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
  (let [values (->> [value]
               flatten
               (mapv canonicalize-acl))]
    (reduce #((get acl-func-map acl-type) %1 %2) rule values)))

(defn add-acl
  "Add various ACL to the incoming rule, based on content of the config-map"
  [rule config-map]
  (->> (select-keys config-map #{:allow :deny})
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
  "Returns true if the given rule contains either a valid method,
  or no specified method."
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

(defn validate-regex-backreferences!
  "Validates that allow and deny back-references actually exist as capture
   groups in the path regex. Throws an exception if a back-reference refers
   to a capture group that doesn't exist."
  [rule]
  (let [group-count (try
                      (-> rule
                          :match-request
                          :path
                          re-pattern
                          (.matcher "")
                          .groupCount)
                      (catch PatternSyntaxException e
                        (reject! "The path regex provided in the rule"
                                 " defined as " (pprint-rule rule)
                                 " is invalid: " (.getMessage e))))
        get-br-list (fn [match-str]
                      (map #(Integer/parseInt (second %))
                           (re-seq #"\$(\d+)" match-str)))
        get-certname-list (fn [rule]
                            (cond
                              (string? rule) (list rule)
                              (map? rule) (list (get rule :certname ""))
                              (sequential? rule) (for [x rule]
                                                 (if (map? x) (get x :certname "") x))
                              :else (list "")))
        largest-br (fn [match]
                     (let [br-list (mapcat get-br-list
                                           (get-certname-list match))]
                       (when (> (count br-list) 0)
                         (apply max br-list))))
        largest-allow-br (or (largest-br (:allow rule)) 0)
        largest-deny-br (or (largest-br (:deny rule)) 0)]
    (doseq [[largest field] [[largest-allow-br "allow"]
                             [largest-deny-br "deny"]]
            :when (> largest group-count)]
      (reject! "The " field " field provided in the rule specified as "
               (pprint-rule rule) " contains the back reference '$"
               largest "' which refers to a capture group in "
               "the regex that doesn't exist."))))

(defn validate-auth-config-rule!
  "Tests to see if the given map contains the proper data to define an auth
  rule. Returns the provided rule if successful, otherwise throws an exception
  with a useful error message."
  [rule]
  (when-not (map? rule)
    (reject! "An authorization rule should be specified as a map."))
  (when-not (:match-request rule)
    (reject! "An authorization rule must contain a 'match-request' section."))
  (doseq [k [:path :type]]
    (when-not (contains? (:match-request rule) k)
      (reject! "The authorization rule specified as " (pprint-rule rule)
               " does not contain a '" (name k) "' key.")))
  (doseq [k [:sort-order :name]]
    (when-not (get rule k)
      (reject! "The authorization rule specified as " (pprint-rule rule)
               " does not contain a '" (name k) "' key.")))
  (when (or (not (integer? (:sort-order rule)))
            (< (:sort-order rule) 1)
            (> (:sort-order rule) 999))
    (reject! "The sort-order set in the authorization rule specified as "
             (pprint-rule rule) " is invalid. It should be a number "
             "from 1 to 999."))
  (if (:allow-unauthenticated rule)
    (if (some #{:deny :allow} (keys rule))
      (reject! "Authorization rule specified as  " (pprint-rule rule)
               " cannot have allow or deny if allow-unauthenticated."))
    (when-not (some #{:deny :allow} (keys rule))
      (reject! "Authorization rule specified as " (pprint-rule rule)
               " must contain either a 'deny' or 'allow' rule.")))
  (when-not (string? (:type (:match-request rule)))
    (reject! "The type set in the authorization rule specified "
             "as " (pprint-rule rule) " should be a "
             "string that is either 'path' or 'regex'."))
  (let [type (-> rule :match-request :type name str/lower-case)]
    (when-not (or (= type "path") (= type "regex"))
      (reject! "The type set in the authorization rule specified "
               "as " (pprint-rule rule) " is invalid. "
               "It should be set to either 'path' or 'regex'.")))
  (when-not (string? (:path (:match-request rule)))
    (reject! "The path set in the authorization rule specified as "
             (pprint-rule rule) " is invalid. "
             "It should be a string."))
  (when-not (valid-method? rule)
    (reject! "The method specified in the authorization rule specified as "
             (pprint-rule rule) " is invalid. "
             "It should be either a string or list of strings that is "
             "equal to one of the following methods: '"
             (str/join "', '" (sort valid-methods)) "'"))
  (when (= "regex" (-> rule :match-request :type name str/lower-case))
    (validate-regex-backreferences! rule))
  (doseq [[type aces] (select-keys rule [:allow :deny])]
    (if (vector? aces)
      (when-not (every? #(or (string? %) (map? %)) aces)
        (reject! "The " (name type) " list in the rule specified as "
                 (pprint-rule rule)
                 " contains one or more aces that are not maps or strings."))
      (when-not (or (map? aces) (string? aces))
        (reject! "The ACE '" aces "' in the '" (name type) "' field of "
                 "the rule specified as " (pprint-rule rule) " is invalid. "
                 "It should be a string or a map with keys :extensions or :certname."))))
  (when-let [query-params (:query-params (:match-request rule))]
    (when-not (map? query-params)
      (reject! "Rule query-params must be a map."))
    (doseq [param (keys query-params)
            :let [value (get query-params param)]]
      (when-not (keyword? param)
        (reject! "The query-param '" param "' in the rule specified as "
                 (pprint-rule rule) " is invalid. It should be a string."))
      (when-not (or (string? value)
                    (vector? value))
        (reject! "The query-param value for '" param "' in the rule "
                 "specified as " (pprint-rule rule) " is invalid. "
                 "It should be a string or list of strings."))
      (when (vector? value)
        (when-not (every? string? value)
          (reject! "The '" param "' query-param in the rule specified as "
                   (pprint-rule rule) " contains one or more values that "
                   "are not strings.")))))
  rule)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(defn validate-auth-config!
  "Validates the given authorization service configuration. If an invalid
  configuration is found an IllegalArgumentException will be thrown, otherwise
  the input config will be returned."
  [config]
  (when-not config
    (reject! "Missing authorization service configuration."))
  (when-not (map? config)
    (reject! "The authorization service configuration is not a map."))
  (let [allow-header-cert-info (:allow-header-cert-info config)]
    (when (and (not (nil? allow-header-cert-info))
               (not (ks/boolean? allow-header-cert-info)))
      (reject! "allow-header-cert-info is not a boolean.")))
  (when-not (= 1 (:version config))
    (reject! "Unsupported or missing version in configuration file. "
             "Supported versions are: 1"))
  (when-not (vector? (:rules config))
    (reject! "The authorization service configuration rules is not a list."))
  (doseq [rule (:rules config)]
    (validate-auth-config-rule! rule))
  (doseq [[name rules] (group-by :name (:rules config))]
    (when-not (= 1 (count rules))
      (reject! "Duplicate rules named '" name "'. "
               "Rules must be uniquely named.")))
  config)

(schema/defn transform-config :- [rules/Rule]
  "Transforms the (validated) authorization service config into a list of Rules
   that work with the authorization code. Assumes config has been validated via
   `validate-auth-config!`."
  [config]
  (->> config
       (map config->rule)
       rules/sort-rules))
