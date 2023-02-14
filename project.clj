(defproject puppetlabs/trapperkeeper-authorization "1.0.1-SNAPSHOT"
  :description "Trapperkeeper authorization system"
  :url "http://github.com/puppetlabs/trapperkeeper-authorization"
  :license {:name "Apache License, Version 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0.html"}

  :min-lein-version "2.7.1"

  :parent-project {:coords [puppetlabs/clj-parent "5.3.0"]
                   :inherit [:managed-dependencies]}

  ;; Abort when version ranges or version conflicts are detected in
  ;; dependencies. Also supports :warn to simply emit warnings.
  ;; requires lein 2.2.0+.
  :pedantic? :abort

  :dependencies [[org.clojure/clojure]

                 [org.clojure/tools.logging]
                 [slingshot]
                 [prismatic/schema]
                 [ring/ring-codec]

                 [puppetlabs/kitchensink]
                 [puppetlabs/trapperkeeper]
                 [puppetlabs/rbac-client]
                 [puppetlabs/ring-middleware]
                 [puppetlabs/ssl-utils]
                 [puppetlabs/i18n]]

  ;; By declaring a classifier here and a corresponding profile below we'll get an additional jar
  ;; during `lein jar` that has all the code in the test/ directory. Downstream projects can then
  ;; depend on this test jar using a :classifier in their :dependencies to reuse the test utility
  ;; code that we have.
  :classifiers [["test" :testutils]]

  :profiles {:dev {:aliases {"ring-example"
                             ["trampoline" "run"
                              "-b" "./examples/ring_app/bootstrap.cfg"
                              "-c" "./examples/ring_app/ring-example.conf"]}
                   :source-paths ["examples/ring_app/src"]
                   :dependencies [[puppetlabs/trapperkeeper-webserver-jetty9]
                                  [puppetlabs/trapperkeeper nil :classifier "test" :scope "test"]
                                  [puppetlabs/kitchensink nil :classifier "test" :scope "test"]
                                  [org.clojure/tools.namespace "1.4.1"]
                                  [org.bouncycastle/bcprov-jdk18on]
                                  [org.bouncycastle/bcpkix-jdk18on]
                                  [ring/ring-mock]]}
             :testutils {:source-paths ^:replace ["test"]}}

  ;; this plugin is used by jenkins jobs to interrogate the project version
  :plugins [[lein-parent "0.3.9"]
            [puppetlabs/i18n "0.9.3"]]

  :lein-release        {:scm          :git
                        :deploy-via   :lein-deploy}

  :deploy-repositories [["releases" {:url "https://clojars.org/repo"
                                     :username :env/clojars_jenkins_username
                                     :password :env/clojars_jenkins_password
                                     :sign-releases false}]
                        ["snapshots" "http://nexus.delivery.puppetlabs.net/content/repositories/snapshots/"]]

  :main puppetlabs.trapperkeeper.main)
