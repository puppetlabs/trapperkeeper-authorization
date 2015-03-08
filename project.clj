(def tk-authz-version "0.0.1")

(defproject puppetlabs/trapperkeeper-authorization tk-authz-version
  :description "TrapperKeeper authorization system"
  :license {:name "Apache License, Version 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0.html"}

  ;; Abort when version ranges or version conflicts are detected in
  ;; dependencies. Also supports :warn to simply emit warnings.
  ;; requires lein 2.2.0+.
  :pedantic? :abort

  :dependencies [[org.clojure/clojure "1.6.0"]
                 ;; Logging
                 [org.clojure/tools.logging "0.2.6"]
                 ;; Filesystem utilities
                 [me.raynes/fs "1.4.5"]
                 [org.clojure/tools.cli "0.3.0"]
                 [prismatic/schema "0.2.2"]
                 [inet.data "0.5.5"]
                 [clj-time "0.5.1"]
                 [puppetlabs/typesafe-config "0.1.1"]
                 [puppetlabs/ssl-utils "0.8.0"]]

  ;; By declaring a classifier here and a corresponding profile below we'll get an additional jar
  ;; during `lein jar` that has all the code in the test/ directory. Downstream projects can then
  ;; depend on this test jar using a :classifier in their :dependencies to reuse the test utility
  ;; code that we have.
  :classifiers [["test" :testutils]]

  :profiles {:dev {:dependencies [[spyscope "0.1.4"]
                                  [puppetlabs/kitchensink ~"1.0.0" :classifier "test"]]
                   :injections [(require 'spyscope.core)]}
             :testutils {:source-paths ^:replace ["test"]}}

  ;; this plugin is used by jenkins jobs to interrogate the project version
  :plugins [[lein-project-version "0.1.0"]
            [lein-release "1.0.5"]]

  :lein-release        {:scm          :git
                        :deploy-via   :lein-deploy}

  :deploy-repositories [["releases" {:url "https://clojars.org/repo"
                                     :username :env/clojars_jenkins_username
                                     :password :env/clojars_jenkins_password
                                     :sign-releases false}]
                        ["snapshots" "http://nexus.delivery.puppetlabs.net/content/repositories/snapshots/"]])