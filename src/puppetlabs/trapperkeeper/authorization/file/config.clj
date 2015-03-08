(ns puppetlabs.trapperkeeper.authorization.file.config
  (:require [schema.core :as schema]
            [clojure.string :as str]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.config.typesafe :as pl-config]
            [inet.data.ip :as ip])
  (:import com.typesafe.config.Config))

(defmacro dbg [x] `(let [x# ~x] (println "dbg:" '~x "=" x#) x#))

;; From Config rule to Rule

(defn config->map
  "Given a configuration returns a map suitable for use in our internal configuration
  representation."
  [config]
  {:pre  [(instance? Config config)]
   :post [(map? %)]}
  (-> config
      (.root)
      (.unwrapped)
      (pl-config/nested-java-map->map)))


(defn- method
  "Returns the method key of a given config map, or :any if none"
  [config-map]
  (keyword (get config-map :method :any)))

(defn- build-rule
  "Build a new Rule based on the provided config-map"
  [config-map]
  (let [rule-type (keyword (get config-map :type :path))]
    (if (= rule-type :path)
      (-> (rules/new-path-rule (config-map :path) (method config-map)))
      (-> (rules/new-regex-rule (config-map :path) (method config-map))))))

(def acl-func-map
  "This is a function map to allow a programmatic execution of allow/deny directives"
  {
    :allow #(rules/allow %1 %2)
    :allow-ip #(rules/allow-ip %1 %2)
    :deny #(rules/deny %1 %2)
    :deny-ip #(rules/deny-ip %1 %2)
  })

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

(schema/defn config->rule :- rules/Rule
  [config :- Config]
  (let [m (config->map config)]
    (if (contains? m :path)
      (-> m
          build-rule
          (add-acl m))
      (throw (Exception. "Invalid config - missing required `path` key")))))

(schema/defn config->rules :- rules/Rules
  [config :- Config]
  (if (.hasPath config "rules")
    (->> (.getConfigList config "rules") (map config->rule) vec)
    (throw (.Exception "Invalid config no rules key"))))