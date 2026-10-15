"use strict";

/* Regulatory references printed in the evidence report.
 * Kept in a separate file so they can be reviewed and updated without touching the code.
 * Always check them against the current official texts (EUR-Lex, Normattiva, ACN). */
window.MPM_REFS = {
  checked: "2026-10-14",
  items: [
    {
      ref: { it: "Direttiva (UE) 2022/2555 (NIS2), art. 21, par. 2, lett. e)", en: "Directive (EU) 2022/2555 (NIS2), Art. 21(2)(e)" },
      what: {
        it: "Sicurezza dell'acquisizione, dello sviluppo e della manutenzione dei sistemi informatici e di rete, compresa la gestione e la divulgazione delle vulnerabilità.",
        en: "Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.",
      },
      how: {
        it: "Il rapporto documenta l'identificazione delle vulnerabilità Microsoft presenti sui dispositivi e la loro correzione con priorità basata sul rischio.",
        en: "The report documents which Microsoft vulnerabilities affect the devices and their risk-based remediation.",
      },
    },
    {
      ref: { it: "D.Lgs. 4 settembre 2024, n. 138, art. 24", en: "Italian Legislative Decree 138/2024, Art. 24" },
      what: {
        it: "Misure tecniche, operative e organizzative adeguate e proporzionate per la gestione dei rischi per la sicurezza informatica (recepimento dell'art. 21 NIS2).",
        en: "Appropriate and proportionate technical, operational and organisational cybersecurity risk-management measures (transposes NIS2 Art. 21).",
      },
      how: {
        it: "Fornisce evidenza dell'applicazione della misura di gestione delle vulnerabilità sul perimetro analizzato.",
        en: "Provides evidence that the vulnerability-handling measure is applied to the assessed scope.",
      },
    },
    {
      ref: { it: "ACN, specifiche di base (Determinazione n. 379907/2025): ID.RA-01", en: "ACN baseline specifications (Determination 379907/2025): ID.RA-01" },
      what: {
        it: "Le vulnerabilità degli asset sono identificate, convalidate e registrate.",
        en: "Vulnerabilities in assets are identified, validated and recorded.",
      },
      how: {
        it: "Elenco, per dispositivo, delle vulnerabilità per cui manca la correzione, confrontando la build installata con quella che la contiene.",
        en: "Per-device list of vulnerabilities still unfixed, comparing the installed build with the build that contains the fix.",
      },
    },
    {
      ref: { it: "ACN, specifiche di base: ID.RA-08", en: "ACN baseline specifications: ID.RA-08" },
      what: {
        it: "Sono stabiliti processi per la ricezione, l'analisi e la risposta alle divulgazioni di vulnerabilità.",
        en: "Processes are established for receiving, analysing and responding to vulnerability disclosures.",
      },
      how: {
        it: "Monitoraggio continuo dei bollettini Microsoft, del CSIRT Italia, del catalogo CISA KEV e di EPSS, con i bollettini CSIRT Italia ricevuti riportati nel rapporto; priorità e scadenze secondo la politica indicata. Il piano va approvato dagli organi di amministrazione.",
        en: "Continuous monitoring of Microsoft advisories, CSIRT Italia bulletins, the CISA KEV catalog and EPSS, with the CSIRT Italia bulletins received listed in the report; priorities and deadlines follow the stated policy. The plan must be approved by the management body.",
      },
    },
    {
      ref: { it: "ACN, specifiche di base: PR.PS-02", en: "ACN baseline specifications: PR.PS-02" },
      what: {
        it: "Il software è mantenuto, sostituito e rimosso in base al rischio; gli aggiornamenti di sicurezza sono installati tempestivamente.",
        en: "Software is maintained, replaced and removed commensurate with risk; security updates are installed promptly.",
      },
      how: {
        it: "Aggiornamento da installare per ogni dispositivo, con data limite e indicazione dei ritardi rispetto alla politica.",
        en: "Update to install for each device, with a deadline and any delay against the policy.",
      },
    },
    {
      ref: { it: "ACN, specifiche di base: ID.RA-06", en: "ACN baseline specifications: ID.RA-06" },
      what: {
        it: "Le risposte al rischio sono scelte, pianificate, tracciate e comunicate.",
        en: "Risk responses are chosen, prioritised, planned, tracked and communicated.",
      },
      how: {
        it: "Piano di intervento con decisione per ogni azione (installare, mitigare, accettare il rischio) e motivazione.",
        en: "Action plan with a decision for each action (install, mitigate, accept the risk) and its rationale.",
      },
    },
  ],
};
