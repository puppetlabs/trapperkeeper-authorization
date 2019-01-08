(ns puppetlabs.trapperkeeper.authorization.acl-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [clojure.string :as str]
            [slingshot.test :refer :all]
            [schema.test :as schema-test]))

(use-fixtures :once schema-test/validate-schemas)

(deftest test-compare-entry
  (testing "deny before allow"
    (let [allow-host (acl/new-domain :allow {:certname "www.google.com"})
          deny-host (acl/new-domain :deny {:certname "www.google.com"})]
      (is (= -1 (acl/ace-compare deny-host allow-host)))
      (is (= 1 (acl/ace-compare allow-host deny-host)))))
  (testing "existing allow before new allow"
    (let [allow-host-1 (acl/new-domain :allow {:certname "www.first.com"})
          allow-host-2 (acl/new-domain :allow {:certname "www.second.com"})]
      (is (= 1 (acl/ace-compare allow-host-1 allow-host-2)))
      (is (= 1 (acl/ace-compare allow-host-2 allow-host-1)))))
  (testing "existing deny before new deny"
    (let [deny-host-1 (acl/new-domain :deny {:certname "www.first.com"})
          deny-host-2 (acl/new-domain :deny {:certname "www.second.com"})]
      (is (= 1 (acl/ace-compare deny-host-1 deny-host-2)))
      (is (= 1 (acl/ace-compare deny-host-2 deny-host-1))))))

(def valid-names
  ["spirit.mars.nasa.gov"
   "ratchet.2ndsiteinc.com"
   "a.c.ru"
   ])

(deftest test-valid-names-ace
  (doseq [name valid-names]
    (let [acl (acl/new-domain :allow {:certname name})]
      (testing (str name " match input name")
        (is (acl/match? acl {:certname name :extensions {}}))))))

(def valid-names-wildcard
  [ "abc.12seps.edu.phisher.biz" "www.google.com" "slashdot.org"])

(deftest test-valid-names-ace-wildcard
  (doseq [name valid-names-wildcard]
    (let [name-split (str/split name #"\.")]
      (doseq [i (range 1 (count name-split))]
        (let [host (str/join "." (concat ["*"] (reverse (take i (reverse name-split)))))
              acl (acl/new-domain :allow {:certname host})]
          (testing (str host " match input name")
            (is (acl/match? acl {:certname name :extensions {}})))
          (testing (str host " doesn't match www.testsite.gov")
            (is (not (acl/match? acl {:certname "www.testsite.gov" :extensions {}}))))
          (testing (str host " doesn't match hosts that differ in the first non-wildcard segment")
            (let [other-split (str/split name #"\.")
                  pos (- (count other-split) i)
                  other (str/join "." (assoc other-split pos (str "test" (nth other-split pos))))]
              (is (not (acl/match? acl {:certname other :extensions {}}))))))))))

(deftest test-fqdn
  (testing "match a similar PQDN"
    (is (not (acl/match? (acl/new-domain :allow {:certname "spirit.mars.nasa.gov."}) {:certname "spirit.mars.nasa.gov"
                                                                                      :extensions {}})))))

(deftest test-regex
  (let [acl (acl/new-domain :allow {:certname "/^(test-)?host[0-9]+\\.other-domain\\.(com|org|net)$|some-domain\\.com/"})]
    (doseq [host ["host5.other-domain.com" "test-host12.other-domain.net" "foo.some-domain.com"]]
      (testing (str host "match regex")
        (is (acl/match? acl {:certname host :extensions {}}))))
    (doseq [host ["'host0.some-other-domain.com" ""]]
      (testing (str host " doesn't match regex")
        (is (not (acl/match? acl {:certname host :extensions {}})))))))

(deftest test-backreference-interpolation
  (testing "injecting backreference values"
    (let [acl (acl/new-domain :allow {:certname "$1.$2.domain.com"})]
      (is (= (:value (acl/interpolate-backreference acl ["a" "b"])) ["com" "domain" "b" "a"])))))

(deftest test-empty-acl
  (testing "it is empty"
    (is (= 0 (count acl/empty-acl)))))

(deftest test-acl-creation
  (testing "not empty when allowing a domain"
    (is (not= 0 (count (acl/allow {:certname "www.google.com"})))))
  (testing "not empty when denying a domain"
    (is (not= 0 (count (acl/deny {:certname "www.google.com"}))))))

(deftest test-acl-ordering
  (testing "deny ACEs ordered before allow ACEs"
    (let [expected-acl [(acl/new-domain :deny {:certname "*.domain.com"})
                        (acl/new-domain :deny {:certname "my.domain.com"})
                        (acl/new-domain :allow {:certname "*.domain.com"})
                        (acl/new-domain :allow {:certname "my.domain.com"})]]
      (testing "when allow ACEs added first"
        (is (= expected-acl (-> (acl/allow {:certname "*.domain.com"})
                                (acl/allow {:certname "my.domain.com"})
                                (acl/deny {:certname "*.domain.com"})
                                (acl/deny {:certname "my.domain.com"})
                                vec))))
      (testing "when deny ACEs added first"
        (is (= expected-acl (-> (acl/deny {:certname "*.domain.com"})
                                (acl/deny {:certname "my.domain.com"})
                                (acl/allow {:certname "*.domain.com"})
                                (acl/allow {:certname "my.domain.com"})
                                vec))))
      (testing "when ACEs added in mixed order"
        (is (= expected-acl (-> (acl/allow {:certname "*.domain.com"})
                                (acl/deny {:certname "*.domain.com"})
                                (acl/deny {:certname "my.domain.com"})
                                (acl/allow {:certname "my.domain.com"})
                                vec)))))))

(deftest test-acl-certname-matching
  (let [acl (-> (acl/allow {:certname "*.domain.com"})
                (acl/deny {:certname "*.test.org"}))]
    (testing "allowing by name"
      (is (acl/allowed? acl {:certname "test.domain.com" :extensions {}})))
    (testing "denying by name"
      (is (not (acl/allowed? acl {:certname "www.test.org" :extensions {}}))))
    (testing "no match is deny"
      (is (not (acl/allowed? acl {:certname "www.google.com" :extensions {}}))))))

(deftest test-global-allow
  (let [acl (acl/allow {:certname "*"})]
    (testing "should allow anything"
      (is (acl/allowed? acl {:certname "anything" :extensions {}})))))

(deftest test-acl-certname-matching-with-captures
  (testing "matching backreference of simple name"
    (let [acl (acl/allow {:certname "$1.google.com"})]
      (is (acl/allowed? acl {:certname "www.google.com" :extensions {}} {:captures ["www"]}))))
  (testing "matching backreference of opaque name"
    (let [acl (acl/allow {:certname "$1"})]
      (is (acl/allowed? acl {:certname "c216f41a-f902-4bfb-a222-850dd957bebb"
                             :extensions {}}
                        {:captures ["c216f41a-f902-4bfb-a222-850dd957bebb"]}))))
  (testing "matching backreference of name"
    (let [acl (acl/allow {:certname "$1"})]
      (is (acl/allowed? acl {:certname "admin.mgmt.nym1"
                             :extensions {}}
                        {:captures ["admin.mgmt.nym1"]})))))

(defn challenge
  ([extensions]
   (challenge "sylvia.plath.net" extensions))
  ([certname extensions]
   (let [default-extensions {:foo "foo"
                             :baz "baz"
                             :quux "quux"}]
     {:certname certname
      :extensions (merge default-extensions extensions)})))

(deftest test-extension-matching
  (testing "when using extensions in an ACL"
    (testing "with scalar matching"
      (let [allowed? (partial acl/allowed? (acl/allow {:extensions {:tradition "confessional"
                                                                    :author "plath"}}))
            !allowed? (comp not allowed?)]
        (is (allowed? (challenge {:tradition "confessional" :author "plath"})))
        (is (!allowed? (challenge {:tradition "surrealist" :author "plath"})))
        (is (!allowed? (challenge {:tradition "surrealist" :author "burroughs"})))
        (is (!allowed? (challenge {})))
        (is (!allowed? (challenge {:style "cutup" :publisher "knopf"})))))

    (testing "with list matching"
      (let [allowed? (partial acl/allowed?
                              (acl/allow {:extensions {:style ["sonnet" "prose" "sestina"]
                                                       :author "olds"}}))
            !allowed? (comp not allowed?)]
        (is (allowed? (challenge {:style "prose" :author "olds"})))
        (is (allowed? (challenge {:style "sestina" :author "olds"})))
        (is (allowed? (challenge {:style "sonnet" :author "olds"})))
        (is (!allowed? (challenge {:style "haiku" :author "olds"})))
        (is (!allowed? (challenge {:style "sestina" :author "burroughs"})))))

    (testing "with raw OIDs in the rules"
      (let [oid-map {"1.2.3.4.5.6.7" :gnarly
                     "7.6.5.4.3.2.1" :times}
            allowed? #(acl/allowed? (-> (acl/allow {:extensions {:author "olds"
                                                                 :1.2.3.4.5.6.7 "foo"}})
                                        (acl/deny {:extensions {:7.6.5.4.3.2.1 "bar"}}))
                                    %
                                    {:oid-map oid-map})
            !allowed? (comp not allowed?)]

        (is (allowed? (challenge {:gnarly "foo"
                                  :author "olds"})))
        (is (!allowed? (challenge {:gnarly "bar"})))
        (is (!allowed? (challenge {:times "bar"})))
        (is (!allowed? (challenge {:times "bar"
                                   :author "olds"
                                   :gnarly "foo"})))))
    (testing "with a varied ACL"
      (let [allowed? (partial acl/allowed?
                              (-> (acl/allow {:extensions {:style ["sonnet" "prose" "sestina"]}})
                                  (acl/allow {:certname "new.confessional.org"})
                                  (acl/deny {:extensions {:length "epic"}})
                                  (acl/deny {:extensions {:length "epic"
                                                          :style "formalist"}})
                                  (acl/deny {:extensions {:style "slam"}})
                                  (acl/deny {:certname "neo.formalism.com"})
                                  (acl/deny {:extensions {:author "gioia"}})
                                  (acl/allow {:extensions {:style "haiku"
                                                           :author "plath"}})))
            !allowed? (comp not allowed?)]
        (is (allowed? (challenge "new.confessional.org" {:style "sonnet"})))
        (is (allowed? (challenge "new.confessional.org"
                                 {:style "haiku" :author "plath"})))
        (is (allowed? (challenge {:style "prose"})))
        (is (allowed? (challenge {:style "sestina" :author "plath"})))
        (is (allowed? (challenge "new.confessional.org" {})))
        (is (allowed? (challenge "whatever.com" {:length "short" :style "prose"})))
        (is (!allowed? (challenge "new.confessional.org" {:length "epic" :style "haiku"})))
        (is (!allowed? (challenge "whatever.com" {:length "short" :style "cut up"})))
        (is (!allowed? (challenge "new.confessional.org" {:style "haiku"
                                                          :length "epic"
                                                          :author "plath"})))
        (is (!allowed? (challenge "new.confessional.org" {:style "slam" :author "plath"})))
        (is (!allowed? (challenge "new.confessional.org" {:style "sonnet" :author "gioia"})))
        (is (!allowed? (challenge "neo.formalism.com" {:style "haiku" :author "plath"})))))))

(deftest test-rbac-allowed
  (let [is-permitted? (fn [subject permission] (and (= permission "let:me:in") (= subject "good")))
        acl #{(acl/new-domain :allow {:rbac {:permission "12:34:56"}})
              (acl/new-domain :allow {:rbac {:permission "let:me:in"}})}]
    (testing "allows"
      (is (acl/rbac-allowed? acl "good" is-permitted?)))
    (testing "denies"
      (is (not (acl/rbac-allowed? acl "bad" is-permitted?))))))

(deftest test-bad-rbac-rules
  (testing "deny ACE with rbac permission throws"
    (is (thrown+?
         [:kind :rbac-deny
          :msg "RBAC permissions cannot be used to deny access. Permission: 'keep:me:out'"]
         (acl/new-domain :deny {:rbac {:permission "keep:me:out"}}))))

  (testing "RBAC permission string formatted wrong"
    (is (thrown? RuntimeException (acl/new-domain :allow {:rbac {:permission "badpermission"}})))))
