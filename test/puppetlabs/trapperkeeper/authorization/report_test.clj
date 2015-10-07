(ns puppetlabs.trapperkeeper.authorization.report-test
  (:require [clojure.test :refer :all]
            [schema.test :as schema-test]
            [puppetlabs.trapperkeeper.authorization.report :as report]
            [puppetlabs.trapperkeeper.authorization.testutils :refer [request]]))

(use-fixtures :once schema-test/validate-schemas)

(deftest test-new-report-from-request
  (let [report (report/new-report (request "here") "www.domain.org")]
    (testing "should embed the request"
      (is (= {:path "here" :method "GET" :ip "127.0.0.1" :name "www.domain.org"} (:request report))))
    (testing "should have no matches"
      (is (= 0 (count (:matches report)))))))

(deftest test-append-rule-report
  (let [blank-report (report/new-report (request "here") "www.domain.org")
        report (report/append-rule-report {:rule "path/to/resource" :match :no :acl-match []} blank-report)]
    (testing "should add one entry"
      (is (= 1 (count (:matches report))))
      (is (= {:rule "path/to/resource" :match :no :acl-match []} (first (:matches report)))))))

(deftest test-new-acl-report
  (testing "empty acl report is empty"
    (is (= 0 (count (report/new-acl-report))))))

(deftest test-appending-acl-report
  (testing "appending one acl report"
    (let [report (-> (report/new-acl-report)
                     (report/append-acl-report {:pattern "test.domain.org" :type :allow :match :yes}))]
      (is (= 1 (count report)))
      (is (= {:pattern "test.domain.org" :type :allow :match :yes} (first report))))))

(deftest test-set-acl-report
  (let [report (->> (report/new-report (request "here") "www.domain.org")
                    (report/append-rule-report {:rule "path/to/resource" :match :no :acl-match []})
                    (report/append-rule-report {:rule "other/resource" :match :yes :acl-match []})
                    (report/append-rule-report {:rule "third/resource" :match :skipped :acl-match []})
                    (report/merge-acl-report [{:pattern "*.daysofwonder.com" :type :allow :match :no}
                                              {:pattern "127.0.0.0/8" :type :deny :match :yes}
                                              ] "other/resource"))
        ]
    (testing "should add an acl report to the right rule"
      (is (= 3 (count (:matches report))))
      (is (= [0 2 0] (map #(count (:acl-match %)) (:matches report))))
      (is (= [{:pattern "*.daysofwonder.com" :type :allow :match :no}
              {:pattern "127.0.0.0/8" :type :deny :match :yes}
              ] (:acl-match (nth (:matches report) 1)))))))
