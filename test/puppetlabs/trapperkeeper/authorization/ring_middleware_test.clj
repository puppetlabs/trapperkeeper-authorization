(ns puppetlabs.trapperkeeper.authorization.ring-middleware-test
  (:require [clojure.test :refer :all]
            [puppetlabs.ssl-utils.core :as ssl-utils]
            [puppetlabs.trapperkeeper.authorization.ring-middleware :as ring-middleware]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.testutils :as testutils]
            [puppetlabs.trapperkeeper.testutils.logging :as logutils]
            [schema.test :as schema-test]
            [ring.util.codec :as ring-codec]
            [ring.util.response :as ring-response]
            [slingshot.test :refer :all])
  (:import (java.io StringWriter)))

(use-fixtures :once schema-test/validate-schemas)

(def test-rule [(-> (testutils/new-rule :path "/path/to/foo")
                    (rules/deny "bad.guy.com")
                    (rules/allow "*.domain.org")
                    (rules/allow "*.test.com"))])

(defn wrap-x-client-dn
  [request name]
  (update-in request [:headers] assoc "x-client-dn" name))

(defn wrap-x-client-verify
  [request verify]
  (update-in request [:headers] assoc "x-client-verify" verify))

(defn wrap-x-client-cert
  [request cert]
  (update-in request [:headers] assoc "x-client-cert" cert))

(defn wrap-successful-x-client-cn
  [request name]
  (-> request
      (wrap-x-client-dn (str "CN=" name))
      (wrap-x-client-verify "SUCCESS")))

(deftest ring-request-to-name-allow-header-cert-info-false-tests
  (testing (str "request to name returns good CN when ssl cert specified and "
                "allow-header-cert-info 'false'")
    (is (= "test.domain.org"
           (ring-middleware/request->name
            (testutils/request "/path/to/resource"
                               :get "127.0.0.1"
                               testutils/test-domain-cert)
            false))))
  (testing (str "request to name nil when ssl cert not specified and "
                "allow-header-cert-info 'false'")
    (is (nil? (ring-middleware/request->name
               (testutils/request "/path/to/resource"
                                  :get "127.0.0.1"
                                  nil)
               false)))),
  (testing (str "request to name returns CN from ssl and not header CN when "
                "allow-header-cert-info 'false'")
    (logutils/with-test-logging
     (is (= "test.domain.org"
            (ring-middleware/request->name
             (-> (testutils/request "/path/to/resource"
                                    :get "127.0.0.1"
                                    testutils/test-domain-cert)
                 (wrap-x-client-dn "O=tester.com, CN=tester.test.org"))
             false))))))

(deftest ring-request-to-name-allow-header-cert-info-true-tests
  (testing (str "request to name returns good CN for RFC 2253 header DN and "
                "allow-header-cert-info true")
    (is (= "tester.test.org"
           (ring-middleware/request->name
            (-> (testutils/request)
                (wrap-x-client-dn "O=tester\\, inc., CN=tester.test.org"))
            true))))
  (testing (str "request to name returns good CN for legacy OpenSSL header DN "
                "and allow-header-cert-info true")
    (is (= "tester.test.org"
           (ring-middleware/request->name
            (-> (testutils/request)
                (wrap-x-client-dn "/O=mytester.com/CN=tester.test.org/L=whoville"))
            true))))
  (testing (str "request to name returns nil CN for legacy OpenSSL DN when no "
                "CN present and allow-header-cert-info true")
    (logutils/with-test-logging
     (is (nil? (ring-middleware/request->name
                (-> (testutils/request)
                    (wrap-x-client-dn "/O=tester/L=whoville"))
                true))))))

(deftest name-verified-tests
  (testing "verified true when not getting name from HTTP headers"
    (is (ring-middleware/verified? (testutils/request) "localhost" false)))
  (testing (str "verified true when getting name from HTTP headers and header "
                "verify was successful")
    (is (ring-middleware/verified? (-> (testutils/request)
                                       (wrap-x-client-verify "SUCCESS"))
                                   "localhost"
                                   true)))
  (testing (str "verified false when getting name from HTTP headers and header "
                "verify was not successful")
    (logutils/with-test-logging
     (is (false? (ring-middleware/verified? (-> (testutils/request)
                                                (wrap-x-client-verify "FAIL"))
                                            "localhost"
                                            true))))))

(deftest ring-request-to-cert-with-ssl-cert
  (testing (str "SSL certificate is extracted from the Ring request when "
                "allow-header-cert-info is false")
    (is (identical? testutils/test-domain-cert
                    (ring-middleware/request->cert
                     (-> (testutils/request)
                         (assoc :ssl-client-cert testutils/test-domain-cert))
                     false)))))

(deftest ring-request-to-cert-from-http-header
  (testing "Extraction of cert from HTTP header in Ring request"
    (letfn [(cert-from-request [header-val]
                               (ring-middleware/request->cert
                                (-> (testutils/request)
                                    (wrap-x-client-cert header-val))
                                true))]
      (testing "succeeds when cert properly URL encoded into the header"
        (is (= "test.domain.org"
               (ssl-utils/get-cn-from-x509-certificate
                (cert-from-request (testutils/url-encoded-cert
                                    testutils/test-domain-cert))))))
      (testing "fails as expected when cert not properly URL encoded"
        (is (thrown+? [:type :puppetlabs.trapperkeeper.authorization.ring-middleware/bad-request
                       :message (str "Unable to URL decode the x-client-cert header: "
                                     "For input string: \"1%\"")]
                      (cert-from-request "%1%2"))))
      (testing "fails as expected when URL encoded properly but base64 content malformed"
        (is (thrown+? [:type :puppetlabs.trapperkeeper.authorization.ring-middleware/bad-request
                       :message (str "Unable to parse x-client-cert into "
                                     "certificate: -----END CERTIFICATE not found")]
                      (cert-from-request
                       "-----BEGIN%20CERTIFICATE-----%0AM"))))
      (testing "fails when cert not in the payload"
        (is (thrown+? [:type :puppetlabs.trapperkeeper.authorization.ring-middleware/bad-request
                       :message "No certs found in PEM read from x-client-cert"]
                      (cert-from-request "NOCERTSHERE"))))
      (testing "fails when more than one cert is in the payload"
        (let [cert-writer (StringWriter.)
              _ (ssl-utils/cert->pem! testutils/test-domain-cert cert-writer)
              _ (ssl-utils/cert->pem! testutils/test-domain-cert cert-writer)
              certs-encoded (ring-codec/url-encode cert-writer)]
          (is (thrown+? [:type :puppetlabs.trapperkeeper.authorization.ring-middleware/bad-request
                         :message (str "Only 1 PEM should be supplied for "
                                       "x-client-cert but 2 found")]
                        (cert-from-request certs-encoded))))))))

(def base-handler
  (fn [_]
    (ring-response/response "hello")))

(defn build-ring-handler
  [rules allow-header-cert-info]
  (-> base-handler
      (ring-middleware/wrap-authorization-check rules allow-header-cert-info)))

(deftest wrap-authorization-check-for-allow-header-cert-info-false-tests
  (testing "wrap-authorization-check for allow-header-cert-info false results in"
    (logutils/with-test-logging
     (let [ring-handler (build-ring-handler test-rule false)]
       (testing "access allowed when cert CN is allowed"
         (let [response (ring-handler (testutils/request
                                       "/path/to/foo"
                                       :get "127.0.0.1"
                                       testutils/test-domain-cert))]
           (is (= 200 (:status response)))
           (is (= "hello" (:body response)))))
       (testing "access denied when cert CN is not in the rule"
         (let [response (ring-handler (testutils/request
                                       "/path/to/foo"
                                       :get "127.0.0.1"
                                       testutils/test-other-cert))]
           (is (= 403 (:status response)))
           (is (= (str "Forbidden request: www.other.org(127.0.0.1) access to "
                       "/path/to/foo (method :get) (authentic: true) denied by "
                       "rule 'test rule'.")
                  (:body response)))))
       (testing "access denied when cert CN is explicitly denied in the rule"
         (let [response (ring-handler (testutils/request
                                       "/path/to/foo"
                                       :get "127.0.0.1"
                                       testutils/test-denied-cert))]
           (is (= 403 (:status response)))
           (is (= (str "Forbidden request: bad.guy.com(127.0.0.1) access to "
                       "/path/to/foo (method :get) (authentic: true) denied by "
                       "rule 'test rule'.")
                  (:body response))))))
     (testing "access denied when deny all"
       (let [app (build-ring-handler [(-> (testutils/new-rule :path "/")
                                          (rules/deny "*"))]
                                     false)]
         (doseq [path ["a" "/" "/hip/hop/" "/a/hippie/to/the/hippi-dee/beat"]]
           (let [req (testutils/request path
                                        :get "127.0.0.1"
                                        testutils/test-domain-cert)
                 {status :status} (app req)]
             (is (= status 403)))))))))

(deftest wrap-authorization-check-for-allow-header-cert-info-true-tests
  (testing "wrap-authorization-check for allow-header-cert-info true results in"
    (logutils/with-test-logging
     (let [ring-handler (build-ring-handler test-rule true)]
       (testing "access allowed when cert CN is allowed"
         (let [response (ring-handler (-> (testutils/request "/path/to/foo"
                                                             :get "127.0.0.1")
                                          (wrap-successful-x-client-cn
                                           "test.domain.org")))]
           (is (= 200 (:status response)))
           (is (= "hello" (:body response)))))
       (testing "access denied when cert CN is not in the rule"
         (let [response (ring-handler (-> (testutils/request
                                           "/path/to/foo"
                                           :get "127.0.0.1")
                                          (wrap-successful-x-client-cn
                                           "www.other.org")))]
           (is (= 403 (:status response)))
           (is (= (str "Forbidden request: www.other.org(127.0.0.1) access to "
                       "/path/to/foo (method :get) (authentic: true) denied by "
                       "rule 'test rule'.")
                  (:body response)))))
       (testing "access denied when cert CN is explicitly denied in the rule"
         (let [response (ring-handler (-> (testutils/request
                                           "/path/to/foo"
                                           :get "127.0.0.1")
                                          (wrap-successful-x-client-cn
                                           "bad.guy.com")))]
           (is (= 403 (:status response)))
           (is (= (str "Forbidden request: bad.guy.com(127.0.0.1) access to "
                       "/path/to/foo (method :get) (authentic: true) denied by "
                       "rule 'test rule'.")
                  (:body response))))))
     (testing "access denied when deny all"
       (let [app (build-ring-handler [(-> (testutils/new-rule :path "/")
                                          (rules/deny "*"))]
                                     true)]
         (doseq [path ["a" "/" "/hip/hop/" "/a/hippie/to/the/hippi-dee/beat"]]
           (let [req (-> (testutils/request path
                                            :get "127.0.0.1"
                                            testutils/test-domain-cert)
                         (wrap-successful-x-client-cn "test.domain.org"))
                 {status :status} (app req)]
             (is (= status 403)))))))))

(deftest authorization-map-wrapped-into-authorized-request
  (testing "Authorization map wrapped into authorized request when"
    (let [build-ring-handler (partial
                              ring-middleware/wrap-authorization-check
                              (fn [request]
                                (ring-response/response request))
                              [(-> (testutils/new-rule :regex "/.*/")
                                   (assoc :allow-unauthenticated true))])
          ring-handler-with-allow-header-cert-info-false (build-ring-handler false)
          ring-handler-with-allow-header-cert-info-true (build-ring-handler true)]
      (testing "SSL certificate provided and allow-header-cert-info false"
        (let [response (ring-handler-with-allow-header-cert-info-false
                        (testutils/request "/path/to/foo" :get "127.0.0.1"
                                           testutils/test-domain-cert))
              authorization (get-in response [:body :authorization])]
          (is (identical? testutils/test-domain-cert (:certificate authorization))
              "SSL certificate not added to authorization map")
          (is (true? (:authentic? authorization))
              "Unexpected authentic? value for authorization map")
          (is (= "test.domain.org" (:name authorization))
              "Unexpected name for authorization map")))
      (testing "no SSL certificate provided and allow-header-cert-info false"
        (let [response (ring-handler-with-allow-header-cert-info-false
                        (testutils/request))
              authorization (get-in response [:body :authorization])]
          (is (nil? (:certificate authorization))
              "SSL certificate added to authorization map")
          (is (false? (:authentic? authorization))
              "Unexpected authentic? value for authorization map")
          (is (= "" (:name authorization))
              "Unexpected name for authorization map")))
      (testing "header credentials provided and allow-header-cert-info true"
        (let [response (ring-handler-with-allow-header-cert-info-true
                        (-> (testutils/request)
                            (wrap-x-client-cert (testutils/url-encoded-cert
                                                 testutils/test-domain-cert))
                            (wrap-x-client-dn "/O=tester/CN=test.domain.org")
                            (wrap-x-client-verify "SUCCESS")))
              authorization (get-in response [:body :authorization])]
          (is (= "test.domain.org"
                 (ssl-utils/get-cn-from-x509-certificate
                  (:certificate authorization)))
              "x-client certificate not added to authorization map")
          (is (true? (:authentic? authorization))
              "Unexpected authentic? value for authorization map")
          (is (= "test.domain.org" (:name authorization))
              "Unexpected name for authorization map")))
      (testing "no header credentials provided and allow-header-cert-info true"
        (let [response (ring-handler-with-allow-header-cert-info-true
                        (testutils/request))
              authorization (get-in response [:body :authorization])]
          (is (nil? (:certificate authorization))
              "SSL certificate added to authorization map")
          (is (false? (:authentic? authorization))
              "Unexpected authentic? value for authorization map")
          (is (= "" (:name authorization))
              "Unexpected name for authorization map"))))))
