(ns puppetlabs.trapperkeeper.authorization.report
  (:require [schema.core :as schema]
            [puppetlabs.trapperkeeper.authorization.ring :refer [Request]]
            [clojure.string :as str]
            [inet.data.ip :as ip]))

;; Schemas

(def Match
  "A rule can either match, not match, never been tested or been unconditionnally authenticated"
  (schema/enum :yes :no :skipped :allow-unauthenticated))

(def EntryReport
  "Report for an Entry test during a match"
  {:pattern schema/Str :type (schema/enum :allow :deny) :match Match})

(def ACLReport
  "Report for matching a list of Entry"
  [EntryReport])

(def RuleReport
  {:rule schema/Str :match Match :acl-match ACLReport}  )

(def Report
  "A textual report of a rules match"
  {:request {:path schema/Str :method schema/Str :name schema/Str :ip schema/Str}
   :matches [RuleReport]
   })

;; Report handling

(schema/defn new-report :- Report
  "Creates a new report from an incoming Request and client name"
  [request :- Request
   name :- schema/Str]
  (let [{ method :request-method uri :uri ip :remote-addr}  request]
    {:request {:path uri :method (str/upper-case (clojure.core/name method)) :name name :ip ip}
     :matches []}))

(schema/defn deny-all :- Report
  "Changes a report in the case of a deny all"
  [report :- Report]
  report)

(schema/defn append-rule-report :- Report
  "Append a RuleReport to a given report"
  [rule-report :- RuleReport
   report :- Report]
  (assoc report :matches (conj (:matches report) rule-report)))

(schema/defn merge-acl-report :- Report
  [acl-report :- ACLReport
   rule-name :- schema/Str
   report :- Report]
  (letfn [(inject-acl-report [rule-report] (if (= (:rule rule-report) rule-name)
                                               (assoc rule-report :acl-match acl-report)
                                               rule-report))]
    (assoc report :matches (mapv inject-acl-report (:matches report)))))

(defn new-acl-report
  "Creates a blank ACLReport"
  [])

(schema/defn append-acl-report :- ACLReport
  "Append one entry to a given acl report"
  [report :- ACLReport
   entry :- EntryReport]
  (conj report entry))