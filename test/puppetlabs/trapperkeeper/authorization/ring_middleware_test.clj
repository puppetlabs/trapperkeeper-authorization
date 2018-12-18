(ns puppetlabs.trapperkeeper.authorization.ring-middleware-test
  (:require [clojure.test :refer :all]
            [puppetlabs.ssl-utils.core :as ssl-utils]
            [puppetlabs.trapperkeeper.authorization.ring :as ring]
            [puppetlabs.trapperkeeper.authorization.ring-middleware :as ring-middleware]
            [puppetlabs.trapperkeeper.authorization.rules :as rules]
            [puppetlabs.trapperkeeper.authorization.testutils :as testutils]
            [puppetlabs.trapperkeeper.testutils.logging :as logutils]
            [schema.test :as schema-test]
            [ring.mock.request :as ring-mock]
            [ring.util.codec :as ring-codec]
            [ring.util.response :as ring-response]
            [slingshot.test :refer :all])
  (:import (java.io StringWriter)))

(use-fixtures :once schema-test/validate-schemas)

(def test-rule [(-> (testutils/new-rule :path "/path/to/foo")
                    (rules/deny {:certname "bad.guy.com"})
                    (rules/allow {:certname "*.domain.org"})
                    (rules/allow {:certname "*.test.com"}))])

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
        (is (thrown+? [:kind :bad-request
                       :msg (str "Unable to URL decode the x-client-cert header: "
                                     "For input string: \"1%\"")]
                      (cert-from-request "%1%2"))))
      (testing "fails as expected when URL encoded properly but base64 content malformed"
        (is (thrown+? [:kind :bad-request
                       :msg (str "Unable to parse x-client-cert into "
                                     "certificate: -----END CERTIFICATE not found")]
                      (cert-from-request
                       "-----BEGIN%20CERTIFICATE-----%0AM"))))
      (testing "fails when cert not in the payload"
        (is (thrown+? [:kind :bad-request
                       :msg "No certs found in PEM read from x-client-cert"]
                      (cert-from-request "NOCERTSHERE"))))
      (testing "fails when more than one cert is in the payload"
        (let [cert-writer (StringWriter.)
              _ (ssl-utils/cert->pem! testutils/test-domain-cert cert-writer)
              _ (ssl-utils/cert->pem! testutils/test-domain-cert cert-writer)
              certs-encoded (ring-codec/url-encode cert-writer)]
          (is (thrown+? [:kind :bad-request
                         :msg (str "Only 1 PEM should be supplied for "
                                       "x-client-cert but 2 found")]
                        (cert-from-request certs-encoded))))))))

(def base-handler
  (fn [_]
    (ring-response/response "hello")))

(defn build-ring-handler
  [rules allow-header-cert-info]
  (-> base-handler
      (ring-middleware/wrap-authorization-check rules {} allow-header-cert-info nil nil)))

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
           (is (= (str "Forbidden request: /path/to/foo (method :get)."
                       " Please see the server logs for details.")
                  (:body response)))))
       (testing "access denied when cert CN is explicitly denied in the rule"
         (let [response (ring-handler (testutils/request
                                       "/path/to/foo"
                                       :get "127.0.0.1"
                                       testutils/test-denied-cert))]
           (is (= 403 (:status response)))
            (is  = (str "Forbidden request: /path/to/foo (method :get)."
                       " Please see the server logs for details.")))))
     (testing "access denied when deny all"
       (let [app (build-ring-handler [(-> (testutils/new-rule :path "/")
                                          (rules/deny {:certname "*"}))]
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
           (is (= (str "Forbidden request: /path/to/foo (method :get)."
                       " Please see the server logs for details.")
                  (:body response)))))
       (testing "access denied when cert CN is explicitly denied in the rule"
         (let [response (ring-handler (-> (testutils/request
                                           "/path/to/foo"
                                           :get "127.0.0.1")
                                          (wrap-successful-x-client-cn
                                           "bad.guy.com")))]
           (is (= 403 (:status response)))
           (is (= (str "Forbidden request: /path/to/foo (method :get)."
                       " Please see the server logs for details.")
                  (:body response))))))
     (testing "access denied when deny all"
       (let [app (build-ring-handler [(-> (testutils/new-rule :path "/")
                                          (rules/deny {:certname "*"}))]
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
    (let [build-ring-handler (fn [allow-header-cert-info]
                               (ring-middleware/wrap-authorization-check
                                (fn [request]
                                  (ring-response/response request))
                                [(-> (testutils/new-rule :regex "/.*/")
                                     (assoc :allow-unauthenticated true))]
                                {}
                                allow-header-cert-info
                                nil nil))
          ring-handler-with-allow-header-cert-info-false (build-ring-handler false)
          ring-handler-with-allow-header-cert-info-true (build-ring-handler true)]
      (testing "SSL certificate provided and allow-header-cert-info false"
        (let [response (ring-handler-with-allow-header-cert-info-false
                        (testutils/request "/path/to/foo" :get "127.0.0.1"
                                           testutils/test-domain-cert))
              authorization (get-in response [:body :authorization])]
          (is (identical? testutils/test-domain-cert (:certificate authorization))
              "SSL certificate not added to authorization map")
          (is (true? (:authenticated authorization))
              "Unexpected authenticated value for authorization map")
          (is (= "test.domain.org" (:name authorization))
              "Unexpected name for authorization map")))
      (testing "no SSL certificate provided and allow-header-cert-info false"
        (let [response (ring-handler-with-allow-header-cert-info-false
                        (testutils/request))
              authorization (get-in response [:body :authorization])]
          (is (nil? (:certificate authorization))
              "SSL certificate added to authorization map")
          (is (false? (:authenticated authorization))
              "Unexpected authenticated value for authorization map")
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
          (is (true? (:authenticated authorization))
              "Unexpected authenticated value for authorization map")
          (is (= "test.domain.org" (:name authorization))
              "Unexpected name for authorization map")))
      (testing "no header credentials provided and allow-header-cert-info true"
        (let [response (ring-handler-with-allow-header-cert-info-true
                        (testutils/request))
              authorization (get-in response [:body :authorization])]
          (is (nil? (:certificate authorization))
              "SSL certificate added to authorization map")
          (is (false? (:authenticated authorization))
              "Unexpected authenticated value for authorization map")
          (is (= "" (:name authorization))
              "Unexpected name for authorization map"))))))

(deftest authorization-check-test
  (let [rules [(-> (testutils/new-rule :path "/foo/bar")
                   (rules/query-param :baz "qux")
                   (rules/allow {:certname "test.domain.org"}))]
        request (testutils/request
                 "/foo/bar" :get "127.0.0.1" testutils/test-domain-cert)]
    (testing "allows and rejects appropriately"
      (is (rules/authorized? (ring-middleware/authorization-check
                              (ring-mock/query-string request "baz=qux")
                              rules
                              {}
                              false
                              nil nil)))
      (logutils/with-test-logging
        (is (not (rules/authorized? (ring-middleware/authorization-check
                                     request
                                     rules
                                     {}
                                     false
                                     nil nil))))))

    (testing "appends authorization info to the request"
      (let [result (-> (ring-mock/query-string request "baz=qux")
                       (ring-middleware/authorization-check rules {} false nil nil))]
        (is (not (nil? (:request result))))
        (is (not (nil? (get-in result [:request :authorization]))))
        (is (= "test.domain.org" (ring/authorized-name (:request result))))
        (is (= testutils/test-domain-cert
               (ring/authorized-certificate (:request result))))
        (is (= true (ring/authorized-authenticated (:request result))))))))

(deftest authorization-extensions-test
  (testing "when working with ssl extensions"
    (let [;; intentionally leaving out puppet node image name to have a raw oid
          oid-map {"1.3.6.1.4.1.34380.1.1.12" :pp_environment
                   "1.3.6.1.4.1.34380.1.1.13" :pp_role
                   "1.3.6.1.4.1.34380.1.1.1"  :puppet-node-uid
                   "2.5.29.20"               :crl-num}
          exts [;; puppet-node-uid
                {:oid "1.3.6.1.4.1.34380.1.1.1"
                 :critical false
                 :value "ED803750-E3C7-44F5-BB08-41A04433FE2E"}
                ;; pp_environment
                {:oid "1.3.6.1.4.1.34380.1.1.12"
                 :critical false
                 :value "test"}
                ;; pp_role
                {:oid "1.3.6.1.4.1.34380.1.1.13"
                 :critical false
                 :value "com"}
                ;; puppet node image name
                {:oid "1.3.6.1.4.1.34380.1.1.3"
                 :critical false
                 :value "sweet_ami_image"}
                ;; crl num
                {:oid      "2.5.29.20"
                 :critical false
                 :value    (biginteger 23)}]
          expected-exts {:crl-num "23"
                         :1.3.6.1.4.1.34380.1.1.3 "sweet_ami_image"
                         :puppet-node-uid "ED803750-E3C7-44F5-BB08-41A04433FE2E"
                         :pp_environment "test"
                         :pp_role "com"}
          cert (testutils/create-certificate "tea.leaves.thwart.net" exts)

          req (testutils/request "/foo/bar" :get "127.0.0.1" cert)
          auth-check (fn [rules] (ring-middleware/authorization-check req rules oid-map false nil nil))]


      (testing "extensions are set properly"
        (let [;; set up auth rules
              rules [(-> (testutils/new-rule :path "/foo/bar")
                         (rules/allow {:certname "tea.leaves.thwart.net"}))]
              auth-result (auth-check rules)
              extensions (get-in auth-result [:request :authorization :extensions])]

          (is (= expected-exts extensions))
          (is (:authorized auth-result))))

      (testing "authorization works as expected"
        (logutils/with-test-logging

          (let [rules [(-> (testutils/new-rule :path "/foo/bar")
                           (rules/allow {:extensions {:pp_role ["com" "mom"]
                                                      :pp_environment "production"
                                                      :1.3.6.1.4.1.34380.1.1.3 "sweet_ami_image"}}))]]

            (is (not (:authorized (auth-check rules)))))

          (let [rules [(-> (testutils/new-rule :path "/foo/bar")
                           (rules/allow {:certname "tea.leaves.thwart.net"})
                           (rules/allow {:extensions {:pp_role ["foo" "bar"]}})
                           (rules/deny {:extensions {:1.3.6.1.4.1.34380.1.1.3 "sweet_ami_image"}}))]]
            (is (not (:authorized (auth-check rules)))))

          (let [rules [(-> (testutils/new-rule :path "/foo/bar")
                           (rules/allow {:certname "tea.leaves.thwart.net"})
                           (rules/allow {:extensions {:pp_environment "test"}})
                           (rules/deny {:extensions {:1.3.6.1.4.1.34380.1.1.3 "bad_ami_image"}}))]]
            (is (:authorized (auth-check rules))))

          (let [rules [(-> (testutils/new-rule :path "/foo/bar")
                           (rules/allow {:certname "tea.leaves.thwart.net"})
                           (rules/allow {:extensions {:pp_environment "test"}})
                           (rules/deny {:extensions {:1.3.6.1.4.1.34380.1.1.3 "bad_ami_image"
                                                     :pp_environment "production"}}))]]
            (is (:authorized (auth-check rules))))

          (let [rules [(-> (testutils/new-rule :path "/foo/bar")
                           (rules/allow {:certname "tea.leaves.thwart.net"})
                           (rules/allow {:extensions {:pp_environment "test"}})
                           (rules/deny {:extensions {:1.3.6.1.4.1.34380.1.1.3 "sweet_ami_image"
                                                     :pp_environment "test"}}))]]
            (is (not (:authorized (auth-check rules))))))))))
