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
  [:deny :allow])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Private

(defn pprint-rule
  [rule]
  (str/trim (ks/pprint-to-string rule)))

(schema/defn transform-config-rule-to-acl :- acl/ACL
  [{:keys [allow deny]}]
  (let [allow (if (string? allow) [allow] allow)
        deny (if (string? deny) [deny] deny)]
    (let [allow-acl (reduce #(acl/allow %1 %2) acl/empty-acl allow)
          full-acl (reduce #(acl/deny %1 %2) allow-acl deny)]
      full-acl)))

(schema/defn transform-config-rule :- rules/Rule
  [config-rule]
  (let [type (name (.toLowerCase (:type config-rule)))]
    {:type (if (= type "regex") :regex :string)
     :path (re-pattern (:path config-rule))
     :method :any
     :acl (transform-config-rule-to-acl config-rule)}))

(defn validate-auth-config-rule!
  "Tests to see if the given map contains the proper data to define an auth
  rule. Returns the provided rule if successful, otherwise throws an exception
  with a useful error message."
  [rule]
  (when-not (map? rule)
    (throw (IllegalArgumentException. "An authorization rule should be specified as a map")))
  (let [rule-keys (keys rule)]
    (doseq [k required-keys]
      (when-not (some #(= k %) rule-keys)
        (throw (IllegalArgumentException. (str "The authorization rule specified as "
                                               (pprint-rule rule)
                                               " does not contain a '" (name k) "' key.")))))
    (when-not (some #(.contains required-or-key %) rule-keys)
      (throw (IllegalArgumentException.
               (str "Authorization rule specified as  "
                    (pprint-rule rule)
                    " must contain either a 'deny' or 'allow' rule.")))))
  (when-not (string? (:type rule))
    (throw (IllegalArgumentException.
             (str "The type set in the authorization rule specified "
                  "as " (pprint-rule rule) " should be a "
                  "string that is either 'path' or 'regex'."))))
  (let [type (.toLowerCase (:type rule))]
    (when-not (or (= type "path") (= type "regex"))
      (throw (IllegalArgumentException.
               (str "The type set in the authorization rule specified "
                    "as " (pprint-rule rule) " is invalid. "
                    "It should be set to either 'path' or 'regex'.")))))
  (let [{path :path} rule]
    (when-not (string? path)
      (throw (IllegalArgumentException.
               (str "The path set in the authorization rule specified as "
                    (pprint-rule rule) " is invalid. It should be "
                    "a string.")))))
  (when (= (name (:type rule)) "regex")
    (try
      (re-pattern (:path rule))
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
                 (str "The name '" names "' in the '" (name type) "' field of the "
                      "rule specified as " (pprint-rule rule) " is not a string."))))))
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
             "The providede authorization service config is not a list.")))
  (doseq [rule config]
    (validate-auth-config-rule! rule))
  config)

(schema/defn transform-config :- rules/Rules
  "Transforms the authorization service config into a list of Rules that work
  with the authorization code."
  [config]
  (map transform-config-rule config))
