(ns puppetlabs.trapperkeeper.services.authorization.authorization-service-test
  (:require
    [clojure.test :refer :all]
    [clojure.string :as str]
    [puppetlabs.ssl-utils.core :as ssl-utils]
    [puppetlabs.trapperkeeper.app :refer [get-service]]
    [puppetlabs.trapperkeeper.authorization.rules :as rules]
    [puppetlabs.trapperkeeper.authorization.testutils :as testutils]
    [puppetlabs.trapperkeeper.services :refer [defservice]]
    [puppetlabs.trapperkeeper.services.authorization.authorization-service
     :refer [authorization-service]]
    [puppetlabs.rbac-client.protocols.rbac :refer [RbacConsumerService]]
    [puppetlabs.trapperkeeper.testutils.bootstrap :refer [with-app-with-config]]
    [puppetlabs.trapperkeeper.testutils.logging :refer [with-test-logging]]
    [ring.mock.request :as mock]
    [ring.util.response :refer [response]]
    [slingshot.slingshot :refer [throw+]]
    [schema.test :as schema-test])
  (:import (java.io ByteArrayInputStream)
           (java.nio.charset Charset)))

(use-fixtures :once schema-test/validate-schemas)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utilities

(def minimal-config
  "Minimal config required to bootstrap AuthorizationService with
  EchoReverseService as a dependant consumer.

  An empty list representing no rules with an expected behavior of
  default-deny originating in the authorization library itself."
  {:authorization {:version 1 :rules []}})

(def basic-rules
  "Basic config exercising the use case of restricting a catalog to a node"
  [{:match-request
    {:path "/puppet/v3/catalog/([^/]+)"
     :type "regex"
     :method "get"}
    :allow "$1"
    :sort-order 500
    :name "puppetlabs catalog"}])

(def default-rules
  "A representative example list of rules intended to model the defaults"
  [{:match-request
    {:path "/puppet/v3/environments"
     :method "get"
     :type "path"}
    :allow "*"
    :sort-order 500
    :name "puppetlabs environments"}
   {:match-request
    {:path "^/puppet/v3/catalog/([^/]+)$"
     :method "get"
     :type "regex"}
    :allow "$1"
    :sort-order 500
    :name "puppetlabs catalog"}
   {:match-request
    {:path "^/puppet/v3/node/([^/]+)$"
     :method "get"
     :type "regex"}
    :allow "$1"
    :sort-order 500
    :name "puppetlabs node"}
   {:match-request
    {:path "^/puppet/v3/report/([^/]+)$"
     :method "put"
     :type "regex"}
    :allow "$1"
    :sort-order 500
    :name "puppetlabs report"}
   {:match-request
    {:path "/puppet/v3/file"
     :type "path"}
    :allow "*"
    :sort-order 500
    :name "puppetlabs file"}
   {:match-request
    {:path "/puppet/v3/status"
     :method "get"
     :type "path"}
    :allow "*"
    :sort-order 500
    :name "puppetlabs status"}
   {:match-request
    {:path "/puppet-ca/v1/certificate_revocation_list/ca"
     :method "get"
     :type "path"}
    :allow "*"
    :sort-order 500
    :name "puppetlabs crl"}
   {:match-request
    {:path "/puppet-ca/v1/certificate/ca"
     :method "get"
     :type "path"}
    :allow-unauthenticated true
    :sort-order 500
    :name "puppetlabs ca cert"}
   {:match-request
    {:path "/puppet-ca/v1/certificate/"
     :method "get"
     :type "path"}
    :allow-unauthenticated true
    :sort-order 500
    :name "puppetlabs cert"}
   {:match-request
    {:path   "/puppet-ca/v1/certificate_request"
     :method ["get" "put"]
     :type   "path"}
    :allow-unauthenticated true
    :sort-order 500
    :name "puppetlabs csr"}
   {:match-request
    {:path "/puppet/v3/rbac_test"
     :method "get"
     :type "path"}
    :allow {:rbac {:permission "get:test:*"}}
    :sort-order 500
    :name "rbac-test"}])

(def catalog-request-nocert
  "A basic request for a catalog without a valid SSL cert"
  {:uri "/puppet/v3/catalog/localhost"
   :request-method :get
   :remote-addr "127.0.0.1"})

(def base-request
  "A basic request to feed into the tests"
  (testutils/request "/" :get "127.0.0.1" (testutils/create-certificate "test.domain.org") ))

(def unauthenticated-request
  "A basic unauthenticated request to feed into the tests"
  (testutils/request "/" :get "127.0.0.1"))

(defprotocol EchoReverseService
  (echo-reverse [this msg]))

;; A simple service using authorization via ring middleware
(defservice
  echo-reverse-service EchoReverseService
  [[:AuthorizationService wrap-with-authorization-check]]
  (echo-reverse
   [this msg]
   (let [handler (fn [req]
                   (-> req
                       (:body)
                       str
                       str/reverse
                       ((partial str msg))
                       response
                       (assoc :request req)))]
     (wrap-with-authorization-check handler))))

(defservice dummy-rbac-service
  RbacConsumerService
  []
  (is-permitted? [this subject perm-str] true)
  (are-permitted? [this subject perm-strs]
    (vec (repeat (count perm-strs) true)))
  (cert-whitelisted? [this ssl-client-cn] true)
  (cert->subject [this ssl-client-cn]
    {:id #uuid "af94921f-bd76-4b58-b5ce-e17c029a2790"
     :login "api_user"})
  (valid-token->subject [this jwt-str]
    (if (or (not jwt-str) (= "invalid-token" jwt-str))
      (throw+ {:kind :puppetlabs.rbac/invalid-token
               :msg (format "Token: %s" jwt-str)})
      {:login     "test_user"
       :id        #uuid "751a8f7e-b53a-4ccd-9f4f-e93db6aa38ec"
       :group_ids [#uuid "aaaaaaaa-b53a-4ccd-9f4f-e93db6aa38ec"
                   #uuid "bbbbbbbb-b53a-4ccd-9f4f-e93db6aa38ec"]}))
  (status [this level]
    {:service_version "1.2.12",
     :service_status_version 1,
     :detail_level "info",
     :state :running,
     :status {:db_up true,
              :activity_up true}})
  (list-permitted [this token object-type action]
    ["one", "two", "three"])
  (list-permitted-for [this subject object-type action]
    ["four" "five" "six"])
  (subject [this user-id]
    {:id user-id
     :login "anImaginaryUserForTesting"}))

(defn build-ring-handler
  "Build a ring handler around the echo reverse service"
  ([rules]
   (build-ring-handler rules minimal-config))
  ([rules config]
   (fn [request]
     (with-test-logging
      (with-app-with-config
       app
       [echo-reverse-service authorization-service dummy-rbac-service]
       (assoc-in config [:authorization :rules] rules)
       (let [svc (get-service app :EchoReverseService)
             echo-handler (echo-reverse svc "Prefix: ")]
         (echo-handler request)))))))

(defprotocol PlumbingService
  (call-authorization-check [this request] [this request options]))

(defservice plumbing-service PlumbingService
  [[:AuthorizationService authorization-check]]
  (call-authorization-check
   [this request]
   (authorization-check request))
  (call-authorization-check
   [this request options]
   (authorization-check request options)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest ^:integration wrap-handler-test
  (testing "With a default configuration list of rules"
    (let [app (build-ring-handler default-rules)]
      (let [req (assoc base-request :uri "/not/covered/by/default/rules")
            {:keys [status body]} (app req)]
        (is (= status 403))
        (is (= body "global deny all - no rules matched")))
      (let [req (-> base-request
                    (assoc :uri "/puppet/v3/environments")
                    (assoc :body "Hello World!"))
            {:keys [status body]} (app req)]
        (is (= status 200))
        (is (= body "Prefix: !dlroW olleH")))
      (let [req (assoc base-request :uri "/puppet-ca/v1/certificate/ca")
            {:keys [status body]} (app req)]
        (is (= status 200))
        (is (= body "Prefix: ")))))
  (testing "(TK-260) Authorizing unauthenticated requests"
    (let [app (build-ring-handler default-rules)]
      (let [{:keys [status body]} (app unauthenticated-request)]
        (is (= status 403))
        (is (= body "global deny all - no rules matched")))
      (let [req (assoc unauthenticated-request
                       :uri "/puppet-ca/v1/certificate/ca"
                       :body "FOOBAR")
            {:keys [status body]} (app req)]
        (is (= status 200))
        (is (= body "Prefix: RABOOF")))
      (let [req (assoc unauthenticated-request
                       :uri "/puppet-ca/v1/certificate/ca"
                       :ssl-client-cert nil)
            {:keys [status body]} (app req)]
        (is (= 200 status) ":ssl-client-cert with nil value works")
        (is (= body "Prefix: ")))
      (let [req (assoc unauthenticated-request :uri "/not/covered/by/rules")
            {:keys [status body]} (app req)]
        (is (= status 403)))
      (let [req (assoc unauthenticated-request :uri "/puppet/v3/status")
            {:keys [status body]} (app req)]
        (is (= status 403) "Unauthentic requests are denied with allow-unauthenticated false"))))
  (testing "With a minimal config of an empty list of rules"
    (let [app (build-ring-handler [])
          req (testutils/request "/path/to/foo" :get "127.0.0.1" testutils/test-domain-cert)
          {:keys [status body]} (app req)]
      (is (= status 403))
      (is (= body "global deny all - no rules matched"))))
  (testing "With a basic config protecting the catalog"
    (let [app (build-ring-handler basic-rules)
          req (assoc catalog-request-nocert :body "Hello World!")
          {:keys [status body]} (app req)]
      (is (= status 403))
      (is (= body (str "Forbidden request: /puppet/v3/catalog/localhost (method :get)."
                       " Please see the server logs for details.")))))
  (testing "Evaluation against rule with 'method' restrictions"
    (let [app (build-ring-handler default-rules)]
      (let [req (testutils/request "/puppet-ca/v1/certificate_request/ca"
                         :head "127.0.0.1" testutils/test-domain-cert)
            {:keys [status body]} (app req)]
        (is (= status 403))
        (is (= body "global deny all - no rules matched")))
      (let [req (testutils/request "/puppet-ca/v1/certificate_request/ca"
                         :get "127.0.0.1" testutils/test-domain-cert)
            {:keys [status]} (app req)]
        (is (= status 200)))
      (let [req (testutils/request "/puppet-ca/v1/certificate_request/ca"
                         :put "127.0.0.1" testutils/test-domain-cert)
            {:keys [status]} (app req)]
        (is (= status 200))))))

(deftest ^:integration authorized-user-test
  (testing "Authorized user info preserved for request with SSL certificate"
    (let [app (build-ring-handler default-rules)
          req (-> base-request
                  (assoc :uri "/puppet/v3/environments")
                  (assoc :body "Hello World!"))
          authorization (get-in (app req) [:request :authorization])]
      (is (true? (:authenticated authorization)))
      (is (= "test.domain.org" (:name authorization)))
      (is (= "test.domain.org" (ssl-utils/get-cn-from-x509-certificate
                                 (:certificate authorization))))))
  (testing "Authorized user info preserved for request with HTTP header credentials"
    (let [app (build-ring-handler default-rules
                                  (assoc-in minimal-config
                                            [:authorization
                                             :allow-header-cert-info]
                                            true))
          req (-> base-request
                  (assoc :uri "/puppet/v3/environments")
                  (assoc :body "Hello World!")
                  (update-in [:headers] merge
                             {"x-client-dn" "CN=test.domain.org"
                              "x-client-verify" "SUCCESS"
                              "x-client-cert" (testutils/url-encoded-cert
                                                testutils/test-domain-cert)}))
          response (app req)
          authorization (get-in response [:request :authorization])]
      (is (= 200 (:status response)))
      (is (true? (:authenticated authorization)))
      (is (= "test.domain.org" (:name authorization)))
      (is (= "test.domain.org" (ssl-utils/get-cn-from-x509-certificate
                                 (:certificate authorization))))))
  (testing "Bad authorized user info generates bad request error"
    (let [app (build-ring-handler default-rules
                                  (assoc-in minimal-config
                                            [:authorization
                                             :allow-header-cert-info]
                                            true))
          req (-> base-request
                  (assoc :uri "/puppet/v3/environments")
                  (assoc :body "Hello World!")
                  (update-in [:headers] assoc "x-client-cert" "NOCERTS"))
          {:keys [status body headers]} (app req)]
      (is (= status 400))
      (is (= "No certs found in PEM read from x-client-cert" body)))))

(deftest ^:integration query-params-test
  (let [app (build-ring-handler
             [{:match-request
               {:path "/puppet/v3/environments"
                :type "path"
                :query-params {:environment ["test" "prod"]
                               :foo ["bar"]}}
               :allow "*"
               :sort-order 100
               :name "environments"}])
        req (assoc base-request
                   :uri "/puppet/v3/environments"
                   :body "Query Param Test")]
    (testing "request denied - params don't match"
      (let [{:keys [status body]}
            (app (mock/query-string req "environment=dev&foo=bar"))]
        (is (= status 403))
        (is (= body "global deny all - no rules matched"))))
    (testing "request allowed - params match"
      (let [{:keys [status body]}
            (app (mock/query-string req "environment=prod&foo=bar"))]
        (is (= status 200))
        (is (= body "Prefix: tseT maraP yreuQ"))))
    (testing "body unchanged after query param destructuring"
      (let [body-string "body=before authorization"
            body-stream-bytes (->> "UTF-8"
                                   Charset/forName
                                   (.getBytes body-string))
            body-as-input-stream (ByteArrayInputStream. body-stream-bytes)
            {:keys [request]}
            (app (-> req
                     (mock/query-string "environment=prod&foo=bar")
                     (mock/content-type "application/x-www-form-urlencoded")
                     (mock/content-length (count body-stream-bytes))
                     (assoc :body body-as-input-stream)))
            body-after-authorization (:body request)]
        (is (identical? body-as-input-stream body-after-authorization)
            "Body object changed after authorization")
        (is (= body-string (slurp body-after-authorization :encoding "UTF-8"))
            "Body stream content changed after authorization")))))

(deftest ^:integration rule-sorting-test
  (let [req (assoc base-request :uri "/foo" :body "Bar")]
    (testing "rules sorted based on :sort-order"
      (let [app (build-ring-handler
                 [{:match-request
                   {:path "/"
                    :type "path"}
                   :deny "*"
                   :sort-order 800
                   :name "you shall not pass"}
                  {:match-request
                   {:path "/"
                    :type "path"}
                   :allow "*"
                   :sort-order 100
                   :name "access granted"}])
            {:keys [status body]} (app req)]
        (is (= 200 status))
        (is (= "Prefix: raB" body)))
      (let [app (build-ring-handler
                 [{:match-request
                   {:path "/"
                    :type "path"}
                   :allow "*"
                   :sort-order 800
                   :name "access granted"}
                  {:match-request
                   {:path "/"
                    :type "path"}
                   :deny "*"
                   :sort-order 100
                   :name "you shall not pass"}])
            {:keys [status body]} (app req)]
        (is (= 403 status))
        (is (re-matches #"Forbidden.*" body))))

    (testing "rules sorted based on :name"
      (let [app (build-ring-handler
                 [{:match-request
                   {:path "/"
                    :type "path"}
                   :deny "*"
                   :sort-order 5
                   :name "B"}
                  {:match-request
                   {:path "/"
                    :type "path"}
                   :allow "*"
                   :sort-order 5
                   :name "A"}])
            {:keys [status body]} (app req)]
        (is (= 200 status))
        (is (= "Prefix: raB" body)))
      (let [app (build-ring-handler
                 [{:match-request
                   {:path "/"
                    :type "path"}
                   :allow "*"
                   :sort-order 5
                   :name "B"}
                  {:match-request
                   {:path "/"
                    :type "path"}
                   :deny "*"
                   :sort-order 5
                   :name "A"}])
            {:keys [status body]} (app req)]
        (is (= 403 status))
        (is (re-matches #"Forbidden.*" body))))))

(deftest ^:integration authorization-check-test
  (testing "authorization check"
    (let [rules-w-exts (conj basic-rules
                             {:match-request
                              {:path "/puppet/v4/catalog"
                               :type "path"
                               :method "get"}
                              :deny {:extensions {:1.3.6.1.4.1.34380.1.1.3 "bad_ami_image"}}
                              :allow {:extensions {:pp_role ["com" "mom"]}}
                              :sort-order 100
                              :name "puppetlabs v4 catalog"})
          bad-image-ext {:oid "1.3.6.1.4.1.34380.1.1.3"
                         :critical false
                         :value "bad_ami_image"}
          good-image-ext (assoc bad-image-ext :value "sweet_ami_image")
          role-ext {:oid "1.3.6.1.4.1.34380.1.1.13"
                    :critical false
                    :value "com"}
          deniable-cert (testutils/create-certificate "test.domain.org"
                                                      [bad-image-ext role-ext])

          allowable-cert (testutils/create-certificate "test.domain.org"
                                                       [good-image-ext role-ext])
          oid-map {"1.3.6.1.4.1.34380.1.1.13" :pp_role}]
      (with-test-logging
        (with-app-with-config
          app
          [plumbing-service authorization-service dummy-rbac-service]
          (assoc-in minimal-config [:authorization :rules] rules-w-exts)
          (testing "allowed request via extensions"
            (let [req (testutils/request "/puppet/v4/catalog" :get "127.0.0.1" allowable-cert)]
              (is (-> (get-service app :PlumbingService)
                      (call-authorization-check req {:oid-map oid-map})
                      rules/authorized?))))
          (testing "denied request via extensions"
            (let [req (testutils/request "/puppet/v4/catalog" :get "127.0.0.1" deniable-cert)]
              (is (not (-> (get-service app :PlumbingService)
                           (call-authorization-check req {:oid-map oid-map})
                           rules/authorized?)))))
          (testing "allowed request via certname"
            (is (-> (get-service app :PlumbingService)
                    (call-authorization-check
                     (assoc base-request :uri "/puppet/v3/catalog/test.domain.org"))
                    (rules/authorized?))))
          (testing "denied request via certless"
            (is (not (-> (get-service app :PlumbingService)
                         (call-authorization-check catalog-request-nocert)
                         (rules/authorized?))))))))))

(deftest ^:integration subject-alt-names
  (testing "Matching subject-alt-name"
    (let [allowable-alt-names ["testing.domain.org" "foo.domain.org" "domain.foo.org"
                               "test.domain.com" "truly.good.net"]
          deniable-alt-names ["testing.bad.org" "foo.bad.org" "bad.foo.org"
                              "test.bad.com" "lol.naw.edu"]
          allowable-ext (ssl-utils/subject-dns-alt-names allowable-alt-names false)
          deniable-ext (ssl-utils/subject-dns-alt-names deniable-alt-names false)
          allowable-cert (testutils/create-certificate "test.domain.org"
                                                       [allowable-ext])
          deniable-cert (testutils/create-certificate "test.bad.org"
                                                      [deniable-ext])
          ext-rules (conj basic-rules
                          {:match-request
                           {:path "/puppet/v4/catalog"
                            :type "path"
                            :method "get"}
                           :deny {:extensions {:subject-alt-name {:dns-name ["testing.bad.org" "bad.foo.org"]}}}
                           :allow {:extensions {:subject-alt-name {:dns-name ["foo.domain.org" "test.domain.com"]}}}
                           :sort-order 100
                           :name "puppetlabs v4 catalog"})
          certname-rules (conj basic-rules
                               {:match-request
                                {:path "/puppet/v4/catalog"
                                 :type "path"
                                 :method "get"}
                                :deny {:certname "foo.bad.org"}
                                :allow {:certname "testing.domain.org"}
                                :sort-order 100
                                :name "puppetlabs v4 catalog"}
                               {:match-request
                                {:path "/puppet/v6/catalog"
                                 :type "path"
                                 :method "get"}
                                :allow "/good/"
                                :deny "/naw/"
                                :sort-order 100
                                :name "puppetlabs v6 catalog"}
                               {:match-request
                                {:path "/puppet/v5/catalog"
                                 :type "path"
                                 :method "get"}
                                :allow "*.good.net"
                                :deny "*.naw.edu"
                                :sort-order 100
                                :name "puppetlabs v5 catalog"})
          auth-opts {:oid-map {}}]
      (testing "as an extension"
        (with-test-logging
          (with-app-with-config
            app
            [plumbing-service authorization-service dummy-rbac-service]
            (assoc-in minimal-config [:authorization :rules] ext-rules)
            (testing "with allow rule"
              (let [req (testutils/request "/puppet/v4/catalog" :get "127.0.0.1" allowable-cert)]
                (is (-> (get-service app :PlumbingService)
                        (call-authorization-check req auth-opts)
                        rules/authorized?))))
            (testing "with deny rule"
              (let [req (testutils/request "/puppet/v4/catalog" :get "127.0.0.1" deniable-cert)]
                (is (not (-> (get-service app :PlumbingService)
                             (call-authorization-check req auth-opts)
                             rules/authorized?))))))))

      (testing "as a certname match"
        (with-test-logging
          (with-app-with-config
            app
            [plumbing-service authorization-service dummy-rbac-service]
            (assoc-in minimal-config [:authorization :rules] certname-rules)
            (testing "using allowed glob"
              (let [req (testutils/request "/puppet/v5/catalog" :get "127.0.0.1" allowable-cert)]
                (is (-> (get-service app :PlumbingService)
                        (call-authorization-check req auth-opts)
                        rules/authorized?))))

            (testing "using deniable glob"
              (let [req (testutils/request "/puppet/v5/catalog" :get "127.0.0.1" deniable-cert)]
                (is (not (-> (get-service app :PlumbingService)
                             (call-authorization-check req auth-opts)
                             rules/authorized?)))))

            (testing "using allowed regex"
              (let [req (testutils/request "/puppet/v6/catalog" :get "127.0.0.1" allowable-cert)]
                (is (-> (get-service app :PlumbingService)
                        (call-authorization-check req auth-opts)
                        rules/authorized?))))

            (testing "using deniable regex"
              (let [req (testutils/request "/puppet/v6/catalog" :get "127.0.0.1" deniable-cert)]
                (is (not (-> (get-service app :PlumbingService)
                             (call-authorization-check req auth-opts)
                             rules/authorized?)))))

            (testing "with allow rule"
              (let [req (testutils/request "/puppet/v4/catalog" :get "127.0.0.1" allowable-cert)]
                (is (-> (get-service app :PlumbingService)
                        (call-authorization-check req auth-opts)
                        rules/authorized?))))
            (testing "with deny rule"
              (let [req (testutils/request "/puppet/v4/catalog" :get "127.0.0.1" deniable-cert)]
                (is (not (-> (get-service app :PlumbingService)
                             (call-authorization-check req auth-opts)
                             rules/authorized?)))))))))))
