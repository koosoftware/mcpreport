/**
 * QMS core — shared logic for the MCP server and the test scripts.
 *
 * Handles: portable HTTP, auto-login + full cookie jar, csrf-token scraping,
 * the report payload template, the report POST, and CSV parsing.
 *
 * Config via env (set once, stable):
 *   QMS_BASE_URL   default http://54.251.164.99:49999
 *   QMS_USER       login user id
 *   QMS_HASH_PWD   hashPwd value from the login payload (stable hash)
 *     -- or --
 *   QMS_PASS       plaintext password; SHA-256'd into hashPwd
 *   QMS_REPORT_PAGE_PATH  (optional) a path to GET after login to scrape the
 *                  csrf-token, if the report endpoint requires it.
 */

import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import { createHash } from "node:crypto";

export const BASE_URL = process.env.QMS_BASE_URL || "http://54.251.164.99:49999";
const USER = process.env.QMS_USER || "";
const HASH_PWD =
  process.env.QMS_HASH_PWD ||
  (process.env.QMS_PASS ? createHash("sha256").update(process.env.QMS_PASS).digest("hex") : "");
export const REPORT_PAGE_PATH =
  process.env.QMS_REPORT_PAGE_PATH ||
  "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CStartPage";

const LOGIN_PATH = "/QMS700i/servlet/my.com.gms.qms.mnt.servlets.CSignOn?param=SUBMIT";
export const REPORT_PATH = "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateReport";
const MAX_ROWS = 200;

// Report registry. Each entry: a friendly key, a human label, a `description`
// (used by the model to decide when the report is relevant), the input `params`,
// and the servlet identifiers. The hLoad1stRec* fields are captured UI state and
// are sent verbatim — they don't change which report is generated (hRptId does).
export const REPORTS = {
  daily_queue_performance: {
    label: "Daily Queue Performance By Day",
    description:
      "Per-day queue performance metrics for a given date: tickets issued, no-shows, " +
      "tickets served, transfers, total; and average / longest / total waiting time, " +
      "serving time and time spent (HH:MM:SS). One row per day. Use for questions about " +
      "daily queue/branch performance, ticket volume, no-shows, wait times or serving times.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11028",
    hRptType: "D",
    hRptClassId: "1",
    hLoad1stRecId: "99023134",
    hLoad1stRecNm: "AKPK Appointment Ticket Report",
  },
  monthly_queue_performance: {
    label: "Monthly Queue Performance By Day",
    description:
      "Queue performance for a whole month, broken down per day (one row per day in the " +
      "month): tickets issued, no-shows, served, transfers, total; and average / longest / " +
      "total waiting time, serving time and time spent (HH:MM:SS). Use for questions about a " +
      "month's queue/branch performance, daily trends within a month, or monthly totals.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12011",
    hRptType: "M",
    hRptClassId: "1",
    hLoad1stRecId: "99023134",
    hLoad1stRecNm: "AKPK Appointment Ticket Report",
  },
  periodic_queue_performance: {
    label: "Periodically Queue Performance By Day",
    description:
      "Queue performance over a custom date range, broken down per day (one row per day " +
      "between a start and end date): tickets issued, no-shows, served, transfers, total; " +
      "and average / longest / total waiting time, serving time and time spent (HH:MM:SS). " +
      "Use for questions spanning a custom 'from X to Y' period or several days.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13011",
    hRptType: "P",
    hRptClassId: "1",
    hLoad1stRecId: "99023134",
    hLoad1stRecNm: "AKPK Appointment Ticket Report",
  },
  daily_by_service_queue_performance: {
    label: "Daily Queue Performance By Day By Service",
    description:
      "Queue performance for a single date, broken down by service type (one row per " +
      "service: Self Service Terminal, With Appointment - Advisory, With Appointment - Post " +
      "DMP / Less 3 facilities, Without Appointment - Advisory, Without Appointment - Post " +
      "DMP / Less 3 facilities): tickets issued, no-shows, served, waiting and serving times. " +
      "Use for questions comparing services, or about a specific service's performance on a day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11095",
    // This report breaks down by service. We rely on the select-all flags
    // (chkAllSvc=on + hSelectAllServiceFlg=Y) instead of hardcoding install-specific
    // service IDs — verified to return all services. csrf-token is blanked and
    // rptDt is overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&targetST=-1&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=11095&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=-1&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=1&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_by_service_queue_performance: {
    label: "Monthly Queue Performance By Day By Service",
    description:
      "Queue performance for a whole month, broken down by service type (one row per " +
      "service: Self Service Terminal, With Appointment - Advisory, With Appointment - Post " +
      "DMP / Less 3 facilities, Without Appointment - Advisory, Without Appointment - Post " +
      "DMP / Less 3 facilities): tickets served, transfers, totals, waiting and serving times, " +
      "and % within target. Use for questions comparing services over a month, or a specific " +
      "service's monthly performance.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12024",
    // Same by-service report, monthly. Relies on select-all flags (no hardcoded
    // service IDs). csrf-token blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&targetST=-1&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=12024&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=-1&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=1&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_by_service_queue_performance: {
    label: "Periodically Queue Performance By Day By Service",
    description:
      "Queue performance over a custom date range, broken down by service type (one row per " +
      "service: Self Service Terminal, With Appointment - Advisory, With Appointment - Post " +
      "DMP / Less 3 facilities, Without Appointment - Advisory, Without Appointment - Post " +
      "DMP / Less 3 facilities): tickets served, transfers, totals, waiting and serving times, " +
      "and % within target. Use for questions comparing services over a custom 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13024",
    // By-service report over a date range. Relies on select-all flags (no hardcoded
    // service IDs). csrf-token blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&targetST=-1&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=P&hRptId=13024&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=-1&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=1&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_by_service_group_queue_performance: {
    label: "Daily Queue Performance By Day By Service By Service Group",
    description:
      "Queue performance for a single date, broken down by service type within a service " +
      "group: tickets served, transfers, totals, waiting and serving times, and % within " +
      "target. Use for questions about service-group performance on a given day, or comparing " +
      "services within a group.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11059",
    // By-service-group report. Both service IDs and the service-group id are dropped
    // (verified that select-all flags return all services and all groups), so this is
    // install-agnostic. csrf-token blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=11059&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_by_service_group_queue_performance: {
    label: "Monthly Queue Performance By Day By Service By Service Group",
    description:
      "Queue performance for a whole month, broken down by service type within a service " +
      "group: tickets served, transfers, totals, waiting and serving times, and % within " +
      "target. Use for questions about service-group performance over a month, or comparing " +
      "services within a group across a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12059",
    // By-service-group, monthly. Service IDs and the service-group id are dropped
    // (select-all flags return all). csrf-token blanked; rptMth/rptYr overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=12059&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_by_service_group_queue_performance: {
    label: "Periodically Queue Performance By Day By Service By Service Group",
    description:
      "Queue performance over a custom date range, broken down by service type within a " +
      "service group: tickets served, transfers, totals, waiting and serving times, and % " +
      "within target. Use for service-group performance over a custom 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13059",
    // By-service-group, date range. Service IDs and the service-group id are dropped
    // (select-all flags return all). csrf-token blanked; rptfrmDt/rpttoDt overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=P&hRptId=13059&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_service_summary_queue_performance: {
    label: "Daily Queue Performance By Service",
    description:
      "Queue performance for a single date summarized by service type (one row per service: " +
      "Self Service Terminal, With/Without Appointment categories): tickets served, transfers, " +
      "totals, waiting and serving times, and % within target. Similar to the 'By Day By " +
      "Service' report but a per-service summary for the date. Use when the user asks for a " +
      "service-level summary of a day's performance.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11023",
    // Per-service summary report. Service IDs dropped (select-all works). csrf-token
    // blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&targetST=-1&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=11023&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=-1&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=1&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_service_summary_queue_performance: {
    label: "Monthly Queue Performance By Service",
    description:
      "Queue performance for a whole month summarized by service type (one row per service " +
      "for the month, not per day): tickets served, transfers, totals, waiting and serving " +
      "times, and % within target. Use when the user wants a service-level summary of a " +
      "month's performance (monthly totals per service).",
    period: "monthly", // input: YYYY-MM
    hRptId: "12006",
    // Per-service monthly summary. Service IDs dropped (select-all works). csrf-token
    // blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&targetST=-1&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=12006&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=-1&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=1&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_service_summary_queue_performance: {
    label: "Periodically Queue Performance By Service",
    description:
      "Queue performance over a custom date range summarized by service type (one row per " +
      "service for the whole range, not per day): tickets served, transfers, totals, waiting " +
      "and serving times, and % within target. Use when the user wants a service-level summary " +
      "over a custom 'from X to Y' span. (Differs from periodic_by_service_queue_performance, " +
      "which gives per-day rows.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13006",
    // Per-service range summary. Service IDs dropped (select-all works). csrf-token
    // blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&targetWT=-1" +
      "&targetST=-1&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=P&hRptId=13006&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=-1" +
      "&hSelTgtSt=-1&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=1&hTgtStTypeSelInd=1&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_by_service_teller_queue_performance: {
    label: "Daily Queue Performance By Service By Teller",
    description:
      "Queue performance for a single date, broken down by service type and by teller/staff " +
      "member: tickets served, transfers, totals, waiting and serving times. Use when the user " +
      "asks about teller or staff performance, comparing tellers, or per-teller service " +
      "performance on a given day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11025",
    // Service IDs and the (large) teller list are dropped; relies on select-all flags
    // (chkAllSvc=on + hSelectAllServiceFlg=Y, chkAllTr=on + hSelectAllTellerFlg=Y).
    // csrf-token blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=11025&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_by_service_teller_queue_performance: {
    label: "Monthly Queue Performance By Service By Teller",
    description:
      "Queue performance for a whole month, broken down by service type and by teller/staff " +
      "member: customers served, waiting and serving times. Use for questions about teller/" +
      "staff performance over a month, or comparing tellers across a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12008",
    // Service IDs and teller list dropped; relies on select-all flags. csrf-token
    // blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=12008&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_by_service_teller_queue_performance: {
    label: "Periodically Queue Performance By Service By Teller",
    description:
      "Queue performance over a custom date range, broken down by service type and by teller/" +
      "staff member: customers served, waiting and serving times. Use for teller/staff " +
      "performance over a custom 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13008",
    // Service IDs and teller list dropped; relies on select-all flags. csrf-token
    // blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=P&hRptId=13008&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_by_teller_service_queue_performance: {
    label: "Daily Queue Performance By Teller By Service",
    description:
      "Queue performance for a single date, grouped by teller/staff member then by service " +
      "type (teller-first ordering): customers served, waiting and serving times. Use when " +
      "the user wants a teller-focused breakdown of a day, i.e. each teller's services. " +
      "(Same data as the 'By Service By Teller' report but ordered teller-first.)",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11041",
    // Service IDs and teller list dropped; relies on select-all flags. csrf-token
    // blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=11041&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_by_teller_service_queue_performance: {
    label: "Monthly Queue Performance By Teller By Service",
    description:
      "Queue performance for a whole month, grouped by teller/staff member then by service " +
      "type (teller-first ordering): customers served, waiting and serving times. Use for a " +
      "teller-focused monthly breakdown. (Same data as the monthly 'By Service By Teller' " +
      "report but ordered teller-first.)",
    period: "monthly", // input: YYYY-MM
    hRptId: "12025",
    // Service IDs and teller list dropped; relies on select-all flags. csrf-token
    // blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=12025&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_by_teller_service_queue_performance: {
    label: "Periodically Queue Performance By Teller By Service",
    description:
      "Queue performance over a custom date range, grouped by teller/staff member then by " +
      "service type (teller-first ordering): customers served, waiting and serving times. Use " +
      "for a teller-focused breakdown over a custom 'from X to Y' span. (Same data as the " +
      "periodic 'By Service By Teller' report but ordered teller-first.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13025",
    // Service IDs and teller list dropped; relies on select-all flags. csrf-token
    // blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=P&hRptId=13025&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_by_teller_service_group_queue_performance: {
    label: "Daily Queue Performance By Teller By Service By Service Group",
    description:
      "Queue performance for a single date, grouped by teller/staff member, service type and " +
      "service group: customers served, waiting and serving times. The most detailed daily " +
      "breakdown. Use when the user wants teller performance broken down by service and " +
      "service group on a given day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11058",
    // Combines all three breakdowns. Service IDs, teller list AND service-group id are
    // dropped; relies on select-all flags (all three verified). csrf-token blanked;
    // rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=11058&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_by_teller_service_group_queue_performance: {
    label: "Monthly Queue Performance By Teller By Service By Service Group",
    description:
      "Queue performance for a whole month, grouped by teller/staff member, service type and " +
      "service group: customers served, waiting and serving times. The most detailed monthly " +
      "breakdown. Use when the user wants teller performance broken down by service and " +
      "service group over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12058",
    // Combines all three breakdowns. Service IDs, teller list AND service-group id are
    // dropped; relies on select-all flags. csrf-token blanked; rptMth/rptYr overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=12058&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_by_teller_service_group_queue_performance: {
    label: "Periodically Queue Performance By Teller By Service By Service Group",
    description:
      "Queue performance over a custom date range, grouped by teller/staff member, service " +
      "type and service group: customers served, waiting and serving times. The most detailed " +
      "range breakdown. Use when the user wants teller performance broken down by service and " +
      "service group over a custom 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13058",
    // Combines all three breakdowns. Service IDs, teller list AND service-group id are
    // dropped; relies on select-all flags. csrf-token blanked; rptfrmDt/rpttoDt overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=P&hRptId=13058&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_by_teller_svcgroup_queue_performance: {
    label: "Daily Queue Performance By Teller By Service Group",
    description:
      "Queue performance for a single date, grouped by teller/staff member and service group " +
      "(NOT broken down by individual service): customers served, waiting and serving times. " +
      "Use when the user wants teller performance by service group on a day, without a " +
      "service-level split.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11069",
    // Teller list and service-group id dropped (select-all). No service breakdown here
    // (hSelectAllServiceFlg=N, kept as captured). csrf-token blanked; rptDt overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=11069&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_by_teller_svcgroup_queue_performance: {
    label: "Monthly Queue Performance By Teller By Service Group",
    description:
      "Queue performance for a whole month, grouped by teller/staff member and service group " +
      "(NOT broken down by individual service): customers served, waiting and serving times. " +
      "Use when the user wants teller performance by service group over a month, without a " +
      "service-level split.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12069",
    // Teller list and service-group id dropped (select-all). No service breakdown
    // (hSelectAllServiceFlg=N, as captured). csrf-token blanked; rptMth/rptYr overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=12069&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_by_teller_svcgroup_queue_performance: {
    label: "Periodically Queue Performance By Teller By Service Group",
    description:
      "Queue performance over a custom date range, grouped by teller/staff member and service " +
      "group (NOT broken down by individual service): customers served, waiting and serving " +
      "times. Use for teller performance by service group over a custom 'from X to Y' span, " +
      "without a service-level split.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13069",
    // Teller list and service-group id dropped (select-all). No service breakdown
    // (hSelectAllServiceFlg=N, as captured). csrf-token blanked; rptfrmDt/rpttoDt overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=P&hRptId=13069&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=1" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=Y&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_pattern_analysis_queue_performance: {
    label: "Daily Queue Performance Pattern Analysis",
    description:
      "Queue performance for a single date broken down by time-of-day / hourly slot: ticket " +
      "volume and waiting/serving times per hour. Use when the user asks about busy hours, " +
      "peak times, hourly patterns, or how performance varies across the day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11033",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y
    // (verify with test-timeslot.js). csrf-token blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=11033&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_pattern_analysis_queue_performance: {
    label: "Monthly Queue Performance Pattern Analysis",
    description:
      "Queue performance for a whole month broken down by time-of-day / hour (aggregated " +
      "across the month): ticket volume and waiting/serving times per hour. Use for questions " +
      "about busy/peak hours or hourly patterns over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12016",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y.
    // csrf-token blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=12016&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_pattern_analysis_queue_performance: {
    label: "Periodically Queue Performance Pattern Analysis",
    description:
      "Queue performance over a custom date range broken down by time-of-day / hour " +
      "(aggregated across the range): ticket volume and waiting/serving times per hour. Use " +
      "for hourly/peak-time patterns over a custom 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13016",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y.
    // csrf-token blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P" +
      "&hRptId=13016&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_pattern_analysis_by_service_queue_performance: {
    label: "Daily Queue Performance Pattern Analysis By Service",
    description:
      "Queue performance for a single date broken down by time-of-day / hour AND by service " +
      "type: ticket volume and waiting/serving times per hour per service. Use for questions " +
      "about hourly/peak patterns split by service on a given day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11020",
    // Service ids AND time-of-day slot ids dropped; relies on select-all flags
    // (chkAllSvc=on + hSelectAllServiceFlg=Y, chkAllTod=on + hDayTimeSlotSelInd=Y).
    // csrf-token blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-16&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=11020&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_pattern_analysis_by_service_queue_performance: {
    label: "Monthly Queue Performance Pattern Analysis By Service",
    description:
      "Queue performance for a whole month broken down by time-of-day / hour AND by service " +
      "type (aggregated across the month): ticket volume and waiting/serving times per hour " +
      "per service. Use for hourly/peak patterns split by service over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12003",
    // Service ids AND time-of-day slot ids dropped; relies on select-all flags.
    // csrf-token blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=12003&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_pattern_analysis_by_service_queue_performance: {
    label: "Periodically Queue Performance Pattern Analysis By Service",
    description:
      "Queue performance over a custom date range broken down by time-of-day / hour AND by " +
      "service type (aggregated across the range): ticket volume and waiting/serving times per " +
      "hour per service. Use for hourly/peak patterns split by service over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13003",
    // Service ids AND time-of-day slot ids dropped; relies on select-all flags.
    // csrf-token blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-15&rpttoDt=2026-06-16&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P" +
      "&hRptId=13003&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=Y&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_waiting_distribution_by_service_queue_performance: {
    label: "Daily Queue Waiting Distribution By Service",
    description:
      "Distribution of customer waiting times for a single date, broken down by service type: " +
      "how many customers fall into each waiting-time bucket per service. Use for questions " +
      "about how long people wait, the spread of waiting times, or SLA/target attainment by " +
      "service on a given day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11052",
    // Service ids dropped (select-all). Waiting-interval grouping (WtItvGrpOpt=0,
    // hSelRptWTItvGrp=0, hWTItvSelInd=Y) are fixed option values, kept as captured.
    // csrf-token blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&WtItvGrpOpt=0&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on" +
      "&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=11052&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=0&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=Y&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_waiting_distribution_by_service_queue_performance: {
    label: "Monthly Queue Waiting Distribution By Service",
    description:
      "Distribution of customer waiting times for a whole month, broken down by service type: " +
      "how many customers fall into each waiting-time bucket per service. Use for questions " +
      "about how long people wait or the spread of waiting times by service over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12052",
    // Service ids dropped (select-all). Waiting-interval grouping option values kept.
    // csrf-token blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=01&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&WtItvGrpOpt=0&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on" +
      "&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=12052&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=0&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=Y&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_waiting_distribution_by_service_queue_performance: {
    label: "Periodically Queue Waiting Distribution By Service",
    description:
      "Distribution of customer waiting times over a custom date range, broken down by service " +
      "type: how many customers fall into each waiting-time bucket per service. Use for " +
      "questions about how long people wait or the spread of waiting times by service over a " +
      "'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13052",
    // Service ids dropped (select-all). Waiting-interval grouping option values kept.
    // csrf-token blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&WtItvGrpOpt=0&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
      "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=P&hRptId=13052&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=" +
      "&hSelRptWTItvGrp=0&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=" +
      "&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=" +
      "&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=" +
      "&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=" +
      "&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=Y&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=Y&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_time_pattern_analysis_queue_performance: {
    label: "Daily Time Performance Pattern Analysis",
    description:
      "Time-based performance for a single date broken down by time-of-day / hour: time/" +
      "duration metrics per hour (distinct from the queue Pattern Analysis report). Use for " +
      "questions about time performance or duration patterns across the hours of a day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11030",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y.
    // csrf-token blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=11030&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_time_pattern_analysis_queue_performance: {
    label: "Monthly Time Performance Pattern Analysis",
    description:
      "Time-based performance for a whole month broken down by time-of-day / hour (aggregated " +
      "across the month): time/duration metrics per hour. Use for time-performance or duration " +
      "patterns across the hours of a day, over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12013",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y.
    // csrf-token blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=01&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=12013&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_time_pattern_analysis_queue_performance: {
    label: "Periodically Time Performance Pattern Analysis",
    description:
      "Time-based performance over a custom date range broken down by time-of-day / hour " +
      "(aggregated across the range): time/duration metrics per hour. Use for time-performance " +
      "or duration patterns across the hours of a day, over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13013",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y.
    // csrf-token blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P" +
      "&hRptId=13013&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_time_pattern_analysis_by_service_queue_performance: {
    label: "Daily Time Performance Pattern Analysis By Service",
    description:
      "Time-based performance for a single date broken down by time-of-day / hour AND by " +
      "service type: time/duration metrics per hour per service. Use for time-performance or " +
      "duration patterns across the hours of a day, split by service.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11027",
    // Service ids AND time-of-day slot ids dropped; relies on select-all flags.
    // csrf-token blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=11027&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_time_pattern_analysis_by_service_queue_performance: {
    label: "Monthly Time Performance Pattern Analysis By Service",
    description:
      "Time-based performance for a whole month broken down by time-of-day / hour AND by " +
      "service type (aggregated across the month): time/duration metrics per hour per service. " +
      "Use for hourly time-performance by service over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12010",
    // Service ids AND time-of-day slot ids dropped; relies on select-all flags.
    // csrf-token blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=01&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=12010&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_time_pattern_analysis_by_service_queue_performance: {
    label: "Periodically Time Performance Pattern Analysis By Service",
    description:
      "Time-based performance over a custom date range broken down by time-of-day / hour AND " +
      "by service type (aggregated across the range): time/duration metrics per hour per " +
      "service. Use for hourly time-performance by service over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13010",
    // Service ids AND time-of-day slot ids dropped; relies on select-all flags.
    // csrf-token blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P" +
      "&hRptId=13010&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=Y&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_counter_by_service_queue_performance: {
    label: "Daily Counter Performance By Service Distribution By Counter",
    description:
      "Counter performance for a single date, broken down by counter and by service type: " +
      "tickets served and timing per counter per service. Use for questions about per-counter " +
      "performance, how work is distributed across counters, or counter throughput on a day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11068",
    counters: true, // counters can't be select-all'd; get_report needs a `counters` arg
    // Service ids dropped (select-all works). Counters do NOT support select-all (chkAllCnt
    // alone -> "Unable to generate report"), so the counter id list is injected by buildBody
    // from the `counters` request arg (or QMS_COUNTERS env default). csrf-token blanked;
    // rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=11068&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=Y&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_counter_by_service_queue_performance: {
    label: "Monthly Counter Performance By Service Distribution By Counter",
    description:
      "Counter performance for a whole month, broken down by counter and by service type: " +
      "tickets served and timing per counter per service. Use for per-counter performance or " +
      "how work is distributed across counters over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12068",
    counters: true, // counters can't be select-all'd; get_report needs a `counters` arg
    // Service ids dropped (select-all). Counter id list injected by buildBody from the
    // `counters` arg (or QMS_COUNTERS env default). csrf-token blanked; rptMth/rptYr overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=05&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=12068&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=Y&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_counter_by_service_queue_performance: {
    label: "Periodically Counter Performance By Service Distribution By Counter",
    description:
      "Counter performance over a custom date range, broken down by counter and by service " +
      "type: tickets served and timing per counter per service. Use for per-counter performance " +
      "or how work is distributed across counters over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13068",
    counters: true, // counters can't be select-all'd; get_report needs a `counters` arg
    // Service ids dropped (select-all). Counter id list injected by buildBody from the
    // `counters` arg (or QMS_COUNTERS env default). csrf-token blanked; rptfrmDt/rpttoDt overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P" +
      "&hRptId=13068&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=Y&hBrhInd=N" +
      "&hCounterSelInd=Y&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_counter_by_teller_queue_performance: {
    label: "Daily Counter Performance By Service Distribution By Teller",
    description:
      "Counter-performance metrics for a single date, broken down by service type and by " +
      "teller/staff member (this report groups by teller, NOT by counter). Use for per-teller " +
      "counter/serving performance on a day, split by service.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11067",
    // Despite the name, this groups by teller (hCounterSelInd=N, no counter selection).
    // Service ids AND teller list dropped; relies on select-all flags. csrf-token blanked;
    // rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=11067&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_counter_by_teller_queue_performance: {
    label: "Monthly Counter Performance By Service Distribution By Teller",
    description:
      "Counter-performance metrics for a whole month, broken down by service type and by " +
      "teller/staff member (groups by teller, NOT by counter). Use for per-teller counter/" +
      "serving performance over a month, split by service.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12067",
    // Groups by teller (hCounterSelInd=N). Service ids AND teller list dropped; relies on
    // select-all flags. csrf-token blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=12067&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_counter_by_teller_queue_performance: {
    label: "Periodically Counter Performance By Service Distribution By Teller",
    description:
      "Counter-performance metrics over a custom date range, broken down by service type and " +
      "by teller/staff member (groups by teller, NOT by counter). Use for per-teller counter/" +
      "serving performance over a 'from X to Y' span, split by service.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13067",
    // Groups by teller (hCounterSelInd=N). Service ids AND teller list dropped; relies on
    // select-all flags. csrf-token blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P" +
      "&hRptId=13067&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=1&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=Y&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=Y&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_counter_pattern_analysis_queue_performance: {
    label: "Daily Counter Performance Pattern Analysis",
    description:
      "Counter-performance metrics for a single date broken down by time-of-day / hour: per-hour " +
      "counter activity/throughput. Use for hourly/peak patterns of counter performance on a day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "11017",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y. No service/
    // teller/counter selection. Note: no TimeFormatOpt, hSelTmFmt empty, hTmFmtSelInd=N (kept
    // as captured). csrf-token blanked; rptDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=11017&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=" +
      "&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=" +
      "&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=" +
      "&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=" +
      "&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=" +
      "&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_counter_pattern_analysis_queue_performance: {
    label: "Monthly Counter Performance Pattern Analysis",
    description:
      "Counter-performance metrics for a whole month broken down by time-of-day / hour " +
      "(aggregated across the month): per-hour counter activity/throughput. Use for hourly/peak " +
      "patterns of counter performance over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "12027",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y. No service/
    // teller/counter selection. Time-format off (no TimeFormatOpt, hSelTmFmt empty, hTmFmtSelInd=N).
    // csrf-token blanked; rptMth/rptYr overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=1&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=12027&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=" +
      "&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=" +
      "&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=" +
      "&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=" +
      "&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=" +
      "&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=" +
      "&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
      "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_counter_pattern_analysis_queue_performance: {
    label: "Periodically Counter Performance Pattern Analysis",
    description:
      "Counter-performance metrics over a custom date range broken down by time-of-day / hour " +
      "(aggregated across the range): per-hour counter activity/throughput. Use for hourly/peak " +
      "patterns of counter performance over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "13027",
    // Time-of-day slot ids dropped; relies on chkAllTod=on + hDayTimeSlotSelInd=Y. No service/
    // teller/counter selection. Time-format off (no TimeFormatOpt, hSelTmFmt empty, hTmFmtSelInd=N).
    // csrf-token blanked; rptfrmDt/rpttoDt overridden per request.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=13027&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=99023134&hLoad1stRecNm=AKPK+Appointment+Ticket+Report" +
      "&hLoad1stRecTyp=P&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_customer_rating_by_counter: {
    label: "Daily Customer Rating Analysis By Counter",
    description:
      "Customer rating / feedback analysis for a single date, broken down by counter: ratings " +
      "or satisfaction scores per counter. Use for questions about customer ratings, feedback, " +
      "or satisfaction by counter on a given day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "21003",
    counters: true, // by-counter report; get_report needs a `counters` arg
    // Rating report class (hRptClassId=2, hServiceGrpSelPurpose=0, rating-specific
    // hLoad1stRec*). No service dimension. Counter id list injected by buildBody from the
    // `counters` arg (or QMS_COUNTERS env default). csrf-token blanked; rptDt overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=21003&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=Y&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_customer_rating_by_counter: {
    label: "Monthly Customer Rating Analysis By Counter",
    description:
      "Customer rating / feedback analysis for a whole month, broken down by counter: ratings " +
      "or satisfaction scores per counter. Use for customer ratings/feedback/satisfaction by " +
      "counter over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "22003",
    counters: true, // by-counter report; get_report needs a `counters` arg
    // Rating report class (hRptClassId=2, hServiceGrpSelPurpose=0). Counter id list injected
    // by buildBody from the `counters` arg. csrf-token blanked; rptMth/rptYr overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&csrf-token=" +
      "&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=22003&hRptDataIn=3" +
      "&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=" +
      "&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=" +
      "&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=" +
      "&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=" +
      "&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=" +
      "&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=" +
      "&hLoad1stRecFlg=Y&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=Y&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_customer_rating_by_counter: {
    label: "Periodically Customer Rating Analysis By Counter",
    description:
      "Customer rating / feedback analysis over a custom date range, broken down by counter: " +
      "ratings or satisfaction scores per counter. Use for customer ratings/feedback/satisfaction " +
      "by counter over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23003",
    counters: true, // by-counter report; get_report needs a `counters` arg
    // Rating report class (hRptClassId=2, hServiceGrpSelPurpose=0). Counter id list injected
    // by buildBody from the `counters` arg. csrf-token blanked; rptfrmDt/rpttoDt overridden.
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&csrf-token=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P" +
      "&hRptId=23003&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=Y&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N" +
      "&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_counter_log: {
    label: "Daily Counter Log",
    description:
      "Counter activity log for a single date: counter login/logout, break and event entries " +
      "per counter. Use for questions about counter open/close times, breaks, or a raw " +
      "activity log of counters on a given day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "51004",
    // Log report class (hRptClassId=5) — different endpoint (CGenerateLogReport) and a smaller
    // log-specific payload (hQELogType, hLogParam=Init, hQEFormatInd=N). csrf-token blanked;
    // rptDt overridden per request.
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=51004&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=&hSelTeller=" +
      "&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv&hSelBrhGrpType=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004&hLoad1stRecNm=Daily+Counter+Log" +
      "&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N&hBrhGrpSelInd=N&hBrhInd=N" +
      "&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0&hSelSvcGrpTypInd=N" +
      "&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N&hServTypeSelInd=0" +
      "&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N&hSelectAllTellerFlg=N" +
      "&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_counter_log: {
    label: "Monthly Counter Log",
    description:
      "Counter activity log for a whole month: counter login/logout, break and event entries " +
      "per counter. Use for questions about counter open/close times, breaks, or a per-counter " +
      "activity log over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "52004",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=52004&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=&hSelTeller=" +
      "&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv&hSelBrhGrpType=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004&hLoad1stRecNm=Daily+Counter+Log" +
      "&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N&hBrhGrpSelInd=N&hBrhInd=N" +
      "&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0&hSelSvcGrpTypInd=N" +
      "&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N&hServTypeSelInd=0" +
      "&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N&hSelectAllTellerFlg=N" +
      "&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_counter_log: {
    label: "Periodically Counter Log",
    description:
      "Counter activity log over a custom date range: counter login/logout, break and event " +
      "entries per counter. Use for questions about counter open/close times, breaks, or a " +
      "per-counter activity log over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53004",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53004&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_customer_log: {
    label: "Daily Customer Log",
    description:
      "Customer activity log for a single date: raw per-customer ticket/event entries. Use for " +
      "questions about individual customer ticket events or a raw customer activity log on a day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "51014",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=51014&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=&hSelTeller=" +
      "&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv&hSelBrhGrpType=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004&hLoad1stRecNm=Daily+Counter+Log" +
      "&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N&hBrhGrpSelInd=N&hBrhInd=N" +
      "&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0&hSelSvcGrpTypInd=N" +
      "&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N&hServTypeSelInd=0" +
      "&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N&hSelectAllTellerFlg=N" +
      "&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_customer_log: {
    label: "Monthly Customer Log",
    description:
      "Customer activity log for a whole month: raw per-customer ticket/event entries. Use for " +
      "questions about individual customer ticket events or a raw customer activity log over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "52014",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=52014&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=&hSelTeller=" +
      "&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv&hSelBrhGrpType=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004&hLoad1stRecNm=Daily+Counter+Log" +
      "&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N&hBrhGrpSelInd=N&hBrhInd=N" +
      "&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0&hSelSvcGrpTypInd=N" +
      "&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N&hServTypeSelInd=0" +
      "&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N&hSelectAllTellerFlg=N" +
      "&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_customer_log: {
    label: "Periodically Customer Log",
    description:
      "Customer activity log over a custom date range: raw per-customer ticket/event entries. " +
      "Use for individual customer ticket events or a raw customer activity log over a 'from X " +
      "to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53014",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53014&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_customer_rating_log: {
    label: "Daily Customer Rating Log",
    description:
      "Customer rating log for a single date: raw per-rating entries (each customer's rating/" +
      "feedback record). Use for a raw log of individual customer ratings/feedback on a day.",
    period: "daily", // input: YYYY-MM-DD
    hRptId: "51008",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=51008&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=&hSelTeller=" +
      "&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv&hSelBrhGrpType=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004&hLoad1stRecNm=Daily+Counter+Log" +
      "&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N&hBrhGrpSelInd=N&hBrhInd=N" +
      "&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0&hSelSvcGrpTypInd=N" +
      "&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N&hServTypeSelInd=0" +
      "&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N&hSelectAllTellerFlg=N" +
      "&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_customer_rating_log: {
    label: "Monthly Customer Rating Log",
    description:
      "Customer rating log for a whole month: raw per-rating entries (each customer's rating/" +
      "feedback record). Use for a raw log of individual customer ratings/feedback over a month.",
    period: "monthly", // input: YYYY-MM
    hRptId: "52008",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=52008&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=&hSelTeller=" +
      "&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv&hSelBrhGrpType=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004&hLoad1stRecNm=Daily+Counter+Log" +
      "&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N&hBrhGrpSelInd=N&hBrhInd=N" +
      "&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0&hSelSvcGrpTypInd=N" +
      "&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N&hServTypeSelInd=0" +
      "&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N&hSelectAllTellerFlg=N" +
      "&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_customer_rating_log: {
    label: "Periodically Customer Rating Log",
    description:
      "Customer rating log over a custom date range: raw per-rating entries (each customer's " +
      "rating/feedback record). Use for a raw log of individual customer ratings/feedback over " +
      "a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53008",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53008&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_customer_ticket_log: {
    label: "Daily Customer Ticket Log",
    description:
      "Customer ticket log for a single day: raw per-ticket entries (each ticket issued, " +
      "its service, counter, times). Use for a raw log of individual customer tickets on a " +
      "specific day.",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51010",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-23&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51010&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_customer_ticket_log: {
    label: "Monthly Customer Ticket Log",
    description:
      "Customer ticket log for a whole month: raw per-ticket entries (each ticket issued, " +
      "its service, counter, times). Use for a raw log of individual customer tickets across " +
      "a month.",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52010",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52010&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_customer_ticket_log: {
    label: "Periodically Customer Ticket Log",
    description:
      "Customer ticket log over a custom date range: raw per-ticket entries (each ticket " +
      "issued, its service, counter, times). Use for a raw log of individual customer tickets " +
      "over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53010",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-22&rpttoDt=2026-06-23&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53010&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_idle_log: {
    label: "Daily Idle Log",
    description:
      "Idle log for a single day: raw entries of counter/teller idle periods (when a " +
      "counter was open but not serving). Use for a raw log of idle time on a specific day.",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51009",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51009&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_idle_log: {
    label: "Monthly Idle Log",
    description:
      "Idle log for a whole month: raw entries of counter/teller idle periods (when a " +
      "counter was open but not serving). Use for a raw log of idle time across a month.",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52009",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52009&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_idle_log: {
    label: "Periodically Idle Log",
    description:
      "Idle log over a custom date range: raw entries of counter/teller idle periods (when a " +
      "counter was open but not serving). Use for a raw log of idle time over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53009",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53009&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_question_rating_log: {
    label: "Daily Question Rating Log",
    description:
      "Question rating log for a single day: raw per-response entries of feedback-survey " +
      "questions and the ratings/answers customers gave. Use for a raw log of survey question " +
      "responses on a specific day.",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51007",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51007&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_question_rating_log: {
    label: "Monthly Question Rating Log",
    description:
      "Question rating log for a whole month: raw per-response entries of feedback-survey " +
      "questions and the ratings/answers customers gave. Use for a raw log of survey question " +
      "responses across a month.",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52007",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52007&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_question_rating_log: {
    label: "Periodically Question Rating Log",
    description:
      "Question rating log over a custom date range: raw per-response entries of feedback-survey " +
      "questions and the ratings/answers customers gave. Use for a raw log of survey question " +
      "responses over a 'from X to Y' span.",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53007",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53007&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=N&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_queue_log: {
    label: "Daily Queue Log",
    description:
      "Queue log for a single day: raw per-ticket queue events (each ticket's queueing " +
      "lifecycle — issued, called, served, with timestamps). Use for a raw event-level log of " +
      "the queue on a specific day. (hQEFormatInd=Y.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51006",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51006&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_queue_log: {
    label: "Monthly Queue Log",
    description:
      "Queue log for a whole month: raw per-ticket queue events (each ticket's queueing " +
      "lifecycle — issued, called, served, with timestamps). Use for a raw event-level log of " +
      "the queue across a month. (hQEFormatInd=Y.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52006",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52006&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_queue_log: {
    label: "Periodically Queue Log",
    description:
      "Queue log over a custom date range: raw per-ticket queue events (each ticket's queueing " +
      "lifecycle — issued, called, served, with timestamps). Use for a raw event-level log of " +
      "the queue over a 'from X to Y' span. (hQEFormatInd=Y.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53006",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53006&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_rating_remark_log: {
    label: "Daily Rating Remark Log",
    description:
      "Rating remark log for a single day: raw entries of the free-text remarks/comments " +
      "customers left along with their feedback ratings. Use for a raw log of rating comments " +
      "on a specific day. (hQEFormatInd=Y.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51015",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51015&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_rating_remark_log: {
    label: "Monthly Rating Remark Log",
    description:
      "Rating remark log for a whole month: raw entries of the free-text remarks/comments " +
      "customers left along with their feedback ratings. Use for a raw log of rating comments " +
      "across a month. (hQEFormatInd=Y.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52015",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52015&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_rating_remark_log: {
    label: "Periodically Rating Remark Log",
    description:
      "Rating remark log over a custom date range: raw entries of the free-text remarks/comments " +
      "customers left along with their feedback ratings. Use for a raw log of rating comments " +
      "over a 'from X to Y' span. (hQEFormatInd=Y.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53015",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53015&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_service_log: {
    label: "Daily Service Log",
    description:
      "Service log for a single day: raw per-transaction entries of services rendered (each " +
      "service event with its counter, teller and times). Use for a raw log of services on a " +
      "specific day. (hQEFormatInd=Y.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51003",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51003&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_service_log: {
    label: "Monthly Service Log",
    description:
      "Service log for a whole month: raw per-transaction entries of services rendered (each " +
      "service event with its counter, teller and times). Use for a raw log of services across " +
      "a month. (hQEFormatInd=Y.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52003",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52003&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_service_log: {
    label: "Periodically Service Log",
    description:
      "Service log over a custom date range: raw per-transaction entries of services rendered " +
      "(each service event with its counter, teller and times). Use for a raw log of services " +
      "over a 'from X to Y' span. (hQEFormatInd=Y.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53003",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53003&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_sms_log: {
    label: "Daily SMS Log",
    description:
      "SMS log for a single day: raw entries of SMS notifications sent to customers (e.g. " +
      "ticket/queue alerts), with recipient, message and timestamp. Use for a raw log of SMS " +
      "notifications on a specific day. (hQEFormatInd=Y.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51011",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51011&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_sms_log: {
    label: "Monthly SMS Log",
    description:
      "SMS log for a whole month: raw entries of SMS notifications sent to customers (e.g. " +
      "ticket/queue alerts), with recipient, message and timestamp. Use for a raw log of SMS " +
      "notifications across a month. (hQEFormatInd=Y.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52011",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52011&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_sms_log: {
    label: "Periodically SMS Log",
    description:
      "SMS log over a custom date range: raw entries of SMS notifications sent to customers " +
      "(e.g. ticket/queue alerts), with recipient, message and timestamp. Use for a raw log of " +
      "SMS notifications over a 'from X to Y' span. (hQEFormatInd=Y.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53011",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53011&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_ticket_log: {
    label: "Daily Ticket Log",
    description:
      "Ticket log for a single day: raw per-ticket entries covering every ticket issued by the " +
      "system, with its number, service, status and timestamps. Use for a raw log of all tickets " +
      "on a specific day. (Distinct from Customer Ticket Log. hQEFormatInd=Y.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51002",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51002&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_ticket_log: {
    label: "Monthly Ticket Log",
    description:
      "Ticket log for a whole month: raw per-ticket entries covering every ticket issued by the " +
      "system, with its number, service, status and timestamps. Use for a raw log of all tickets " +
      "across a month. (Distinct from Customer Ticket Log. hQEFormatInd=Y.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52002",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52002&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_ticket_log: {
    label: "Periodically Ticket Log",
    description:
      "Ticket log over a custom date range: raw per-ticket entries covering every ticket issued " +
      "by the system, with its number, service, status and timestamps. Use for a raw log of all " +
      "tickets over a 'from X to Y' span. (Distinct from Customer Ticket Log. hQEFormatInd=Y.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53002",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53002&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_transaction_log: {
    label: "Daily Transaction Log",
    description:
      "Transaction log for a single day: raw per-transaction entries of each service transaction " +
      "processed at a counter (with teller, service, status and times). Use for a raw log of all " +
      "transactions on a specific day. (hQEFormatInd=Y.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51013",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51013&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_transaction_log: {
    label: "Monthly Transaction Log",
    description:
      "Transaction log for a whole month: raw per-transaction entries of each service transaction " +
      "processed at a counter (with teller, service, status and times). Use for a raw log of all " +
      "transactions across a month. (hQEFormatInd=Y.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52013",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52013&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_transaction_log: {
    label: "Periodically Transaction Log",
    description:
      "Transaction log over a custom date range: raw per-transaction entries of each service " +
      "transaction processed at a counter (with teller, service, status and times). Use for a raw " +
      "log of all transactions over a 'from X to Y' span. (hQEFormatInd=Y.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53013",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53013&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_user_log: {
    label: "Daily User Log",
    description:
      "User log for a single day: raw entries of staff/operator user activity (logins, " +
      "actions and counter/teller sessions) with timestamps. Use for a raw log of staff user " +
      "activity on a specific day. (hQEFormatInd=Y.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "51005",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-25&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=D&hRptId=51005&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  monthly_user_log: {
    label: "Monthly User Log",
    description:
      "User log for a whole month: raw entries of staff/operator user activity (logins, " +
      "actions and counter/teller sessions) with timestamps. Use for a raw log of staff user " +
      "activity across a month. (hQEFormatInd=Y.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "52005",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on" +
      "&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on" +
      "&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5&hRptSelBrhCode=" +
      "&hRptIsCorp=false&hRptType=M&hRptId=52005&hSelBrh=&hSelBrhGrp=&hSelServ=&hSelSvcGrp=" +
      "&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  periodic_user_log: {
    label: "Periodically User Log",
    description:
      "User log over a custom date range: raw entries of staff/operator user activity (logins, " +
      "actions and counter/teller sessions) with timestamps. Use for a raw log of staff user " +
      "activity over a 'from X to Y' span. (hQEFormatInd=Y.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "53005",
    path: "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateLogReport",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-24&rpttoDt=2026-06-25&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=5" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=53005&hSelBrh=&hSelBrhGrp=&hSelServ=" +
      "&hSelSvcGrp=&hSelTeller=&hSelCounter=&hSelTgtWt=&hQELogType=&hLogParam=Init&hRptOut=csv" +
      "&hSelBrhGrpType=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=51004" +
      "&hLoad1stRecNm=Daily+Counter+Log&hLoad1stRecTyp=D&hQEFormatInd=Y&hBrhGrpTypeSelInd=N" +
      "&hBrhGrpSelInd=N&hBrhInd=N&hBrhTypeSelInd=0&hBrhGrpSelectionType=0&hBranchGrpSelPurpose=0" +
      "&hSelSvcGrpTypInd=N&hSvcGrpSelInd=N&hServSelInd=N&hTellerSelInd=N&hCounterSelInd=N" +
      "&hServTypeSelInd=0&hSvcGrpSelectionType=0&hServiceGrpSelPurpose=0&hTellerTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hSvcGrpTypSelectionType=0&hUploadFolderNm=&hSelectAllServiceFlg=N" +
      "&hSelectAllTellerFlg=N&hIsDefRpt=Y&hIsUsrRpt=N",
  },
  daily_customer_rating_by_day: {
    label: "Daily Customer Rating Analysis By Day",
    description:
      "Customer rating analysis for a single day, summarized BY DAY (one aggregated row of " +
      "rating scores/feedback metrics for the whole day, not per counter or teller). Use for an " +
      "overall daily customer-satisfaction/rating summary. (Customer Rating class; portable, no " +
      "counters.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21009",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=21009&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_customer_rating_by_day: {
    label: "Monthly Customer Rating Analysis By Day",
    description:
      "Customer rating analysis for a whole month, summarized BY DAY (per-day rows of rating " +
      "scores/feedback metrics across the month). Use for a monthly customer-satisfaction/rating " +
      "summary broken down by day. (Customer Rating class; portable, no counters.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22009",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=22009&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_customer_rating_by_day: {
    label: "Periodically Customer Rating Analysis By Day",
    description:
      "Customer rating analysis over a custom date range, summarized BY DAY (per-day rows of " +
      "rating scores/feedback metrics across the span). Use for a customer-satisfaction/rating " +
      "summary over a 'from X to Y' period broken down by day. (Customer Rating class; portable, " +
      "no counters.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23009",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23009" +
      "&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=" +
      "&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D" +
      "&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N" +
      "&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0" +
      "&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0" +
      "&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N" +
      "&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N" +
      "&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N" +
      "&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N" +
      "&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N" +
      "&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N&hTmPeriodSelInd=N" +
      "&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0" +
      "&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y" +
      "&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_customer_rating_by_ict: {
    label: "Daily Customer Rating Analysis By ICT",
    description:
      "Customer rating analysis for a single day, broken down BY ICT (the input/collection " +
      "terminal or channel customers used to submit their rating). Use for a daily customer-rating " +
      "summary segmented by feedback device/channel. (Customer Rating class; portable, no counters; " +
      "no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21036",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21036&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_customer_rating_by_ict: {
    label: "Monthly Customer Rating Analysis By ICT",
    description:
      "Customer rating analysis for a whole month, broken down BY ICT (the input/collection " +
      "terminal or channel customers used to submit their rating). Use for a monthly customer-rating " +
      "summary segmented by feedback device/channel. (Customer Rating class; portable, no counters; " +
      "no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22036",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22036&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_customer_rating_by_ict: {
    label: "Periodically Customer Rating Analysis By ICT",
    description:
      "Customer rating analysis over a custom date range, broken down BY ICT (the input/collection " +
      "terminal or channel customers used to submit their rating). Use for a customer-rating summary " +
      "over a 'from X to Y' span segmented by feedback device/channel. (Customer Rating class; " +
      "portable, no counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23036",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23036&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_customer_rating_by_service: {
    label: "Daily Customer Rating Analysis By Service",
    description:
      "Customer rating analysis for a single day, broken down BY SERVICE (one row per service " +
      "type showing its rating scores/feedback metrics). Use for a daily customer-satisfaction/" +
      "rating summary segmented by service. (Customer Rating class; portable select-all services, " +
      "no counters.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21002",
    // Portable: hSelServ blank + per-service named fields dropped; rely on chkAllSvc=on +
    // hSelectAllServiceFlg=Y (hServSelInd=Y, hServTypeSelInd=1 kept as the select-all-services state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=21002&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_customer_rating_by_service: {
    label: "Monthly Customer Rating Analysis By Service",
    description:
      "Customer rating analysis for a whole month, broken down BY SERVICE (one row per service " +
      "type showing its rating scores/feedback metrics). Use for a monthly customer-satisfaction/" +
      "rating summary segmented by service. (Customer Rating class; portable select-all services, " +
      "no counters.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22002",
    // Portable: hSelServ blank + per-service named fields dropped; rely on chkAllSvc=on +
    // hSelectAllServiceFlg=Y (hServSelInd=Y, hServTypeSelInd=1 kept as the select-all-services state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=22002&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_customer_rating_by_service: {
    label: "Periodically Customer Rating Analysis By Service",
    description:
      "Customer rating analysis over a custom date range, broken down BY SERVICE (one row per " +
      "service type showing its rating scores/feedback metrics). Use for a customer-satisfaction/" +
      "rating summary over a 'from X to Y' span segmented by service. (Customer Rating class; " +
      "portable select-all services, no counters.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23002",
    // Portable: hSelServ blank + per-service named fields dropped; rely on chkAllSvc=on +
    // hSelectAllServiceFlg=Y (hServSelInd=Y, hServTypeSelInd=1 kept as the select-all-services state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23002" +
      "&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=" +
      "&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D" +
      "&hApplyExpDate=Y&hSelectAllServiceFlg=Y&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N" +
      "&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=1&hBrhTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0" +
      "&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0" +
      "&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N" +
      "&hServSelInd=Y&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N" +
      "&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N" +
      "&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N" +
      "&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N" +
      "&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N&hTmPeriodSelInd=N" +
      "&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0" +
      "&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y" +
      "&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_customer_rating_by_teller: {
    label: "Daily Customer Rating Analysis By Teller",
    description:
      "Customer rating analysis for a single day, broken down BY TELLER (one row per teller/" +
      "staff member showing the rating scores/feedback their customers gave). Use for a daily " +
      "customer-satisfaction/rating summary per teller. (Customer Rating class; portable select-all " +
      "tellers, no counters.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21001",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=D&hRptId=21001&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  monthly_customer_rating_by_teller: {
    label: "Monthly Customer Rating Analysis By Teller",
    description:
      "Customer rating analysis for a whole month, broken down BY TELLER (one row per teller/" +
      "staff member showing the rating scores/feedback their customers gave). Use for a monthly " +
      "customer-satisfaction/rating summary per teller. (Customer Rating class; portable select-all " +
      "tellers, no counters.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22001",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&TimeFormatOpt=1" +
      "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=" +
      "&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=M&hRptId=22001&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  periodic_customer_rating_by_teller: {
    label: "Periodically Customer Rating Analysis By Teller",
    description:
      "Customer rating analysis over a custom date range, broken down BY TELLER (one row per " +
      "teller/staff member showing the rating scores/feedback their customers gave). Use for a " +
      "customer-satisfaction/rating summary over a 'from X to Y' span per teller. (Customer Rating " +
      "class; portable select-all tellers, no counters.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23001",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&TimeFormatOpt=1&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=" +
      "&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on" +
      "&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
      "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on" +
      "&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=" +
      "&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23001" +
      "&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=" +
      "&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D" +
      "&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=Y" +
      "&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0" +
      "&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0" +
      "&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0" +
      "&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=Y&hMthSelInd=N" +
      "&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y&hDayTimeSlotSelInd=N" +
      "&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N" +
      "&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N" +
      "&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N" +
      "&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N&hTmPeriodSelInd=N" +
      "&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0" +
      "&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y" +
      "&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  daily_qos_performance_by_answer: {
    label: "Daily QoS Performance By Answer",
    description:
      "Quality-of-service performance for a single day, broken down BY ANSWER (one row per " +
      "feedback-survey answer option, e.g. each rating/response choice, with how many customers " +
      "chose it and related metrics). Use for a daily breakdown of customer feedback by answer/" +
      "response option. (Customer Rating class; portable, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21013",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21013&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_qos_performance_by_answer: {
    label: "Monthly QoS Performance By Answer",
    description:
      "Quality-of-service performance for a whole month, broken down BY ANSWER (one row per " +
      "feedback-survey answer option, e.g. each rating/response choice, with how many customers " +
      "chose it and related metrics). Use for a monthly breakdown of customer feedback by answer/" +
      "response option. (Customer Rating class; portable, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22013",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22013&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_qos_performance_by_answer: {
    label: "Periodically QoS Performance By Answer",
    description:
      "Quality-of-service performance over a custom date range, broken down BY ANSWER (one row " +
      "per feedback-survey answer option, e.g. each rating/response choice, with how many " +
      "customers chose it and related metrics). Use for a breakdown of customer feedback by " +
      "answer/response option over a 'from X to Y' span. (Customer Rating class; portable, no " +
      "counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23013",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23013&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_qos_performance_by_answer_by_question: {
    label: "Daily QoS Performance By Answer By Question",
    description:
      "Quality-of-service performance for a single day, broken down BY ANSWER within each " +
      "QUESTION (rows per survey question, then per answer/response option, showing how customers " +
      "answered each feedback question). Use for a daily breakdown of feedback answers grouped by " +
      "survey question. (Customer Rating class; portable select-all questions, no counters; no " +
      "time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21012",
    // Portable: hSelQuestion blank + per-question named (survey-text) fields dropped; rely on the
    // proven all-questions default chkAllQues=on + hQuestionSelInd=N (same state all other reports use).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21012&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_qos_performance_by_answer_by_question: {
    label: "Monthly QoS Performance By Answer By Question",
    description:
      "Quality-of-service performance for a whole month, broken down BY ANSWER within each " +
      "QUESTION (rows per survey question, then per answer/response option, showing how customers " +
      "answered each feedback question). Use for a monthly breakdown of feedback answers grouped by " +
      "survey question. (Customer Rating class; portable select-all questions, no counters; no " +
      "time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22012",
    // Portable: hSelQuestion blank + per-question named (survey-text) fields dropped; rely on the
    // proven all-questions default chkAllQues=on + hQuestionSelInd=N (same state all other reports use).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22012&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_qos_performance_by_answer_by_question: {
    label: "Periodically QoS Performance By Answer By Question",
    description:
      "Quality-of-service performance over a custom date range, broken down BY ANSWER within each " +
      "QUESTION (rows per survey question, then per answer/response option, showing how customers " +
      "answered each feedback question). Use for a breakdown of feedback answers grouped by survey " +
      "question over a 'from X to Y' span. (Customer Rating class; portable select-all questions, no " +
      "counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23012",
    // Portable: hSelQuestion blank + per-question named (survey-text) fields dropped; rely on the
    // proven all-questions default chkAllQues=on + hQuestionSelInd=N (same state all other reports use).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23012&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_distribution_by_day_by_question: {
    label: "Daily Rating Distribution By Day By Question",
    description:
      "Rating distribution for a single day, summarized BY DAY and BY QUESTION (the spread of " +
      "rating scores/answer choices across each feedback question — e.g. how many 1-star, 2-star " +
      "etc. each question received). Use for a daily view of how customer ratings are distributed " +
      "per survey question. (Customer Rating class; portable, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21011",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21011&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_distribution_by_day_by_question: {
    label: "Monthly Rating Distribution By Day By Question",
    description:
      "Rating distribution for a whole month, summarized BY DAY and BY QUESTION (the spread of " +
      "rating scores/answer choices across each feedback question — e.g. how many 1-star, 2-star " +
      "etc. each question received). Use for a monthly view of how customer ratings are distributed " +
      "per survey question. (Customer Rating class; portable, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22011",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22011&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_distribution_by_day_by_question: {
    label: "Periodically Rating Distribution By Day By Question",
    description:
      "Rating distribution over a custom date range, summarized BY DAY and BY QUESTION (the spread " +
      "of rating scores/answer choices across each feedback question — e.g. how many 1-star, 2-star " +
      "etc. each question received). Use for a 'from X to Y' view of how customer ratings are " +
      "distributed per survey question. (Customer Rating class; portable, no counters; no time-format " +
      "option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23011",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23011&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_distribution_by_question: {
    label: "Daily Rating Distribution By Question",
    description:
      "Rating distribution for a single day, summarized BY QUESTION (the spread of rating scores/" +
      "answer choices per feedback question, aggregated over the whole day — not broken out by day). " +
      "Use for a daily summary of how customer ratings are distributed across each survey question. " +
      "(Customer Rating class; portable, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21005",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21005&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_distribution_by_question: {
    label: "Monthly Rating Distribution By Question",
    description:
      "Rating distribution for a whole month, summarized BY QUESTION (the spread of rating scores/" +
      "answer choices per feedback question, aggregated over the month — not broken out by day). " +
      "Use for a monthly summary of how customer ratings are distributed across each survey " +
      "question. (Customer Rating class; portable, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22005",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22005&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_distribution_by_question: {
    label: "Periodically Rating Distribution By Question",
    description:
      "Rating distribution over a custom date range, summarized BY QUESTION (the spread of rating " +
      "scores/answer choices per feedback question, aggregated over the span — not broken out by " +
      "day). Use for a 'from X to Y' summary of how customer ratings are distributed across each " +
      "survey question. (Customer Rating class; portable, no counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23005",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23005&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_distribution_by_question_by_ict: {
    label: "Daily Rating Distribution By Question By ICT",
    description:
      "Rating distribution for a single day, summarized BY QUESTION and BY ICT (the spread of " +
      "rating scores per feedback question, further split by the input terminal/channel customers " +
      "used to submit the rating). Use for a daily view of rating distribution per question per " +
      "feedback device/channel. (Customer Rating class; portable, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21037",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21037&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_distribution_by_question_by_ict: {
    label: "Monthly Rating Distribution By Question By ICT",
    description:
      "Rating distribution for a whole month, summarized BY QUESTION and BY ICT (the spread of " +
      "rating scores per feedback question, further split by the input terminal/channel customers " +
      "used to submit the rating). Use for a monthly view of rating distribution per question per " +
      "feedback device/channel. (Customer Rating class; portable, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22037",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22037&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_distribution_by_question_by_ict: {
    label: "Periodically Rating Distribution By Question By ICT",
    description:
      "Rating distribution over a custom date range, summarized BY QUESTION and BY ICT (the spread " +
      "of rating scores per feedback question, further split by the input terminal/channel customers " +
      "used to submit the rating). Use for a 'from X to Y' view of rating distribution per question " +
      "per feedback device/channel. (Customer Rating class; portable, no counters; no time-format " +
      "option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23037",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23037&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_distribution_by_question_by_teller: {
    label: "Daily Rating Distribution By Question By Teller",
    description:
      "Rating distribution for a single day, summarized BY QUESTION and BY TELLER (the spread of " +
      "rating scores per feedback question, further split by teller/staff member). Use for a daily " +
      "view of rating distribution per question per teller. (Customer Rating class; portable " +
      "select-all tellers, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21010",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21010&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=1&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=Y&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_distribution_by_question_by_teller: {
    label: "Monthly Rating Distribution By Question By Teller",
    description:
      "Rating distribution for a whole month, summarized BY QUESTION and BY TELLER (the spread of " +
      "rating scores per feedback question, further split by teller/staff member). Use for a monthly " +
      "view of rating distribution per question per teller. (Customer Rating class; portable " +
      "select-all tellers, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22010",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22010&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=1&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=Y&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_distribution_by_question_by_teller: {
    label: "Periodically Rating Distribution By Question By Teller",
    description:
      "Rating distribution over a custom date range, summarized BY QUESTION and BY TELLER (the " +
      "spread of rating scores per feedback question, further split by teller/staff member). Use " +
      "for a 'from X to Y' view of rating distribution per question per teller. (Customer Rating " +
      "class; portable select-all tellers, no counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23010",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23010&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_distribution_by_teller: {
    label: "Daily Rating Distribution By Teller",
    description:
      "Rating distribution for a single day, summarized BY TELLER (the spread of rating scores/" +
      "answer choices per teller/staff member, aggregated over the whole day — not broken out per " +
      "question). Use for a daily view of how customer ratings are distributed across each teller. " +
      "(Customer Rating class; portable select-all tellers, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21018",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21018&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=1&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=Y&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_distribution_by_teller: {
    label: "Monthly Rating Distribution By Teller",
    description:
      "Rating distribution for a whole month, summarized BY TELLER (the spread of rating scores/" +
      "answer choices per teller/staff member, aggregated over the month — not broken out per " +
      "question). Use for a monthly view of how customer ratings are distributed across each teller. " +
      "(Customer Rating class; portable select-all tellers, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22018",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22018&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=1&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=Y&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_distribution_by_teller: {
    label: "Periodically Rating Distribution By Teller",
    description:
      "Rating distribution over a custom date range, summarized BY TELLER (the spread of rating " +
      "scores/answer choices per teller/staff member, aggregated over the span — not broken out per " +
      "question). Use for a 'from X to Y' view of how customer ratings are distributed across each " +
      "teller. (Customer Rating class; portable select-all tellers, no counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23018",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23018&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_distribution_by_teller_by_question: {
    label: "Daily Rating Distribution By Teller By Question",
    description:
      "Rating distribution for a single day, summarized BY TELLER and BY QUESTION (the spread of " +
      "rating scores per teller/staff member, further split per feedback question). Use for a daily " +
      "view of rating distribution per teller per survey question. (Customer Rating class; portable " +
      "select-all tellers, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21008",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21008&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=1&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=Y&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_distribution_by_teller_by_question: {
    label: "Monthly Rating Distribution By Teller By Question",
    description:
      "Rating distribution for a whole month, summarized BY TELLER and BY QUESTION (the spread of " +
      "rating scores per teller/staff member, further split per feedback question). Use for a monthly " +
      "view of rating distribution per teller per survey question. (Customer Rating class; portable " +
      "select-all tellers, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22008",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22008&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=1&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=Y&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_distribution_by_teller_by_question: {
    label: "Periodically Rating Distribution By Teller By Question",
    description:
      "Rating distribution over a custom date range, summarized BY TELLER and BY QUESTION (the " +
      "spread of rating scores per teller/staff member, further split per feedback question). Use " +
      "for a 'from X to Y' view of rating distribution per teller per survey question. (Customer " +
      "Rating class; portable select-all tellers, no counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23008",
    // Portable: hSelTeller blank + per-teller named fields dropped; rely on chkAllTr=on +
    // hSelectAllTellerFlg=Y (hTellerSelInd=Y, hTellerTypeSelInd=1 kept as the select-all-tellers state).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23008&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=Y&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=1&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=Y" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_distribution_pattern_analysis: {
    label: "Daily Rating Distribution Pattern Analysis",
    description:
      "Rating distribution pattern for a single day broken down BY HOUR / time-of-day (the spread " +
      "of rating scores across each hour of the day, e.g. how ratings vary 07:00, 08:00, ...). Use " +
      "for a daily hourly pattern of how customer ratings are distributed through the day. (Customer " +
      "Rating class; portable select-all time-of-day, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21007",
    // Portable: hSelDayTimeSlot blank + per-hour named fields dropped; rely on the verified
    // time-of-day select-all chkAllTod=on + hDayTimeSlotSelInd=Y (returns all hour slots).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21007&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_distribution_pattern_analysis: {
    label: "Monthly Rating Distribution Pattern Analysis",
    description:
      "Rating distribution pattern for a whole month broken down BY HOUR / time-of-day (the spread " +
      "of rating scores across each hour of the day, e.g. how ratings vary 07:00, 08:00, ...). Use " +
      "for a monthly hourly pattern of how customer ratings are distributed through the day. (Customer " +
      "Rating class; portable select-all time-of-day, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22007",
    // Portable: hSelDayTimeSlot blank + per-hour named fields dropped; rely on the verified
    // time-of-day select-all chkAllTod=on + hDayTimeSlotSelInd=Y (returns all hour slots).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22007&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_distribution_pattern_analysis: {
    label: "Periodically Rating Distribution Pattern Analysis",
    description:
      "Rating distribution pattern over a custom date range broken down BY HOUR / time-of-day (the " +
      "spread of rating scores across each hour of the day, e.g. how ratings vary 07:00, 08:00, ...). " +
      "Use for a 'from X to Y' hourly pattern of how customer ratings are distributed through the day. " +
      "(Customer Rating class; portable select-all time-of-day, no counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23007",
    // Portable: hSelDayTimeSlot blank + per-hour named fields dropped; rely on the verified
    // time-of-day select-all chkAllTod=on + hDayTimeSlotSelInd=Y (returns all hour slots).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23007&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_performance_by_question: {
    label: "Daily Rating Performance By Question",
    description:
      "Rating performance for a single day, summarized BY QUESTION (per feedback question, the " +
      "average rating / performance scores and how it measured against targets). Use for a daily " +
      "summary of customer-rating performance for each survey question. (Customer Rating class; " +
      "portable, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21004",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21004&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_performance_by_question: {
    label: "Monthly Rating Performance By Question",
    description:
      "Rating performance for a whole month, summarized BY QUESTION (per feedback question, the " +
      "average rating / performance scores and how it measured against targets). Use for a monthly " +
      "summary of customer-rating performance for each survey question. (Customer Rating class; " +
      "portable, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22004",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22004&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_performance_by_question: {
    label: "Periodically Rating Performance By Question",
    description:
      "Rating performance over a custom date range, summarized BY QUESTION (per feedback question, " +
      "the average rating / performance scores and how it measured against targets). Use for a " +
      "'from X to Y' summary of customer-rating performance for each survey question. (Customer " +
      "Rating class; portable, no counters; no time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23004",
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23004&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
  daily_rating_performance_pattern_analysis: {
    label: "Daily Rating Performance Pattern Analysis",
    description:
      "Rating performance pattern for a single day broken down BY HOUR / time-of-day (the average " +
      "rating / performance scores across each hour of the day, e.g. how rating performance varies " +
      "07:00, 08:00, ...). Use for a daily hourly pattern of customer-rating performance. (Customer " +
      "Rating class; portable select-all time-of-day, no counters; no time-format option.)",
    period: "daily", // input: date YYYY-MM-DD (rptDt)
    hRptId: "21006",
    // Portable: hSelDayTimeSlot blank + per-hour named fields dropped; rely on the verified
    // time-of-day select-all chkAllTod=on + hDayTimeSlotSelInd=Y (returns all hour slots).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=2026-06-29&rptYr=&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=D&hRptId=21006&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  monthly_rating_performance_pattern_analysis: {
    label: "Monthly Rating Performance Pattern Analysis",
    description:
      "Rating performance pattern for a whole month broken down BY HOUR / time-of-day (the average " +
      "rating / performance scores across each hour of the day, e.g. how rating performance varies " +
      "07:00, 08:00, ...). Use for a monthly hourly pattern of customer-rating performance. (Customer " +
      "Rating class; portable select-all time-of-day, no counters; no time-format option.)",
    period: "monthly", // input: month YYYY-MM (rptMth + rptYr)
    hRptId: "22006",
    // Portable: hSelDayTimeSlot blank + per-hour named fields dropped; rely on the verified
    // time-of-day select-all chkAllTod=on + hDayTimeSlotSelInd=Y (returns all hour slots).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptMth=06&rptYr=2026&rptYearly=&selTgtAvgWt=" +
      "&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=&selTgtTt2=&selTgtTrxSt2=" +
      "&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on&chkAllSvcGrp=on" +
      "&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on" +
      "&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
      "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2&hRptSelBrhCode=&hRptIsCorp=false" +
      "&hRptType=M&hRptId=22006&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=" +
      "&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=" +
      "&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=&hSelAnswer=" +
      "&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=" +
      "&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=" +
      "&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=" +
      "&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=21003" +
      "&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter&hLoad1stRecTyp=D&hApplyExpDate=Y" +
      "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N" +
      "&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0" +
      "&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0&hTgtTtTypeSelInd=0&hIctTypeSelInd=0" +
      "&hTellerTypeSelInd=0&hSvcGrpSelectionType=0&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0" +
      "&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N&hMthSelInd=N&hServSelInd=N&hBrhInd=N" +
      "&hCounterSelInd=N&hTellerSelInd=N&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N" +
      "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N" +
      "&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N" +
      "&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N" +
      "&hTrxGrpSelInd=N&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N" +
      "&hBranchGrpSelPurpose=0&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y" +
      "&hStGrpIsUpdate=Y&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
      "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=",
  },
  periodic_rating_performance_pattern_analysis: {
    label: "Periodically Rating Performance Pattern Analysis",
    description:
      "Rating performance pattern over a custom date range broken down BY HOUR / time-of-day (the " +
      "average rating / performance scores across each hour of the day, e.g. how rating performance " +
      "varies 07:00, 08:00, ...). Use for a 'from X to Y' hourly pattern of customer-rating " +
      "performance. (Customer Rating class; portable select-all time-of-day, no counters; no " +
      "time-format option.)",
    period: "range", // inputs: date_from + date_to (YYYY-MM-DD)
    hRptId: "23006",
    // Portable: hSelDayTimeSlot blank + per-hour named fields dropped; rely on the verified
    // time-of-day select-all chkAllTod=on + hDayTimeSlotSelInd=Y (returns all hour slots).
    payload:
      "csrf-token=&useExpDt=on&useExpDt2=on&rptfrmDt=2026-06-28&rpttoDt=2026-06-29&rptYr=" +
      "&rptYearly=&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
      "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on&chkAllSrvGrpTyp=on" +
      "&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on&chkAllTrans=on&chkAllTod=on" +
      "&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on" +
      "&chkAllIct=on&hiddenBrhGrpTyp=&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=2" +
      "&hRptSelBrhCode=&hRptIsCorp=false&hRptType=P&hRptId=23006&hRptDataIn=3&hRptOut=csv" +
      "&hSelBrh=&hSelMth=&hSelServ=&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=" +
      "&hSelSTItv=&hSelRptWTItvGrp=&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=" +
      "&hSelTgtTt=&hSelQuestion=&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=" +
      "&hSelServPrio=&hSelTgtAvgWt=&hSelTgtAvgSt=&hSelTmFmt=&hSelQuesGrp=&hSelBrhGrpType=" +
      "&hSelTrxSTItv=&hSelTgtTrxSt=&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=" +
      "&hSelTrxGrp=&hSelTmPeriod=&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y" +
      "&hLoad1stRecId=21003&hLoad1stRecNm=Daily+Customer+Rating+Analysis+By+Counter" +
      "&hLoad1stRecTyp=D&hApplyExpDate=Y&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N" +
      "&hSelectAllTellerFlg=N&hSelectAllTrxFlg=N&rptLevel=&rptSelFieldIdList=&hServTypeSelInd=0" +
      "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
      "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
      "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0&hTmFmtSelInd=N" +
      "&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N&hTellerSelInd=N" +
      "&hDayTimeSlotSelInd=Y&hWTItvSelInd=N&hSTItvSelInd=N&hQuestionSelInd=N&hAnswerSelInd=N" +
      "&hTransactionSelInd=N&hBrhGrpSelInd=N&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N" +
      "&hTgtAvgStSelInd=N&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N" +
      "&hTrxSTRangeSelInd=N&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
      "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
      "&hServiceGrpSelPurpose=0&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
      "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=&hSelStdWtP2=" +
      "&hSelStdSt=&hSelStdStP2=",
  },
};

const PAYLOAD_TEMPLATE =
  "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=&rptYr=&rptYearly=&TimeFormatOpt=1" +
  "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
  "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on" +
  "&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
  "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
  "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
  "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false" +
  "&hRptType=D&hRptId=11028&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=" +
  "&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=" +
  "&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=" +
  "&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=" +
  "&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=" +
  "&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=" +
  "&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
  "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
  "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N" +
  "&hSelectAllTrxFlg=N&rptLevel=1&rptSelFieldIdList=0&hServTypeSelInd=0" +
  "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
  "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
  "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0" +
  "&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N" +
  "&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
  "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N" +
  "&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N" +
  "&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N" +
  "&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
  "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
  "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
  "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
  "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=";

export const today = () => new Date().toISOString().slice(0, 10);
export const thisMonth = () => new Date().toISOString().slice(0, 7);
export const isIsoDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));
export const isYearMonth = (s) => /^\d{4}-\d{2}$/.test(s);

/** Human-readable input shape for a report (used by find_reports / list_reports). */
export const inputFor = (r) =>
  r.period === "monthly"
    ? "month YYYY-MM"
    : r.period === "range"
    ? "date_from + date_to (YYYY-MM-DD)"
    : "date YYYY-MM-DD";

// Words too generic to help disambiguate; ignored when scoring search queries.
const SEARCH_STOPWORDS = new Set([
  "the", "a", "an", "of", "for", "and", "or", "to", "in", "on", "by", "with",
  "report", "reports", "show", "me", "give", "get", "find", "what", "whats",
  "how", "many", "is", "are", "was", "were", "do", "does", "did", "my", "our",
  "this", "that", "please", "want", "need", "can", "you", "qms", "analysis",
  "rating", "ratings", // very common across the Customer Rating class — low signal
]);

/**
 * Build a lightweight search index over the REPORTS registry. One entry per
 * report with a tokenized bag of words from its key + label + description, plus
 * period/grain hints. Built once at module load.
 */
const SEARCH_INDEX = Object.entries(REPORTS).map(([key, r]) => {
  const keyWords = key.split(/[_\s]+/).filter(Boolean);
  const labelWords = (r.label || "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const descWords = (r.description || "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return {
    key,
    label: r.label || key,
    period: r.period || "daily",
    description: r.description || r.label || "",
    // weighted: key + label tokens count more than description tokens
    strong: new Set([...keyWords, ...labelWords]),
    weak: new Set(descWords),
  };
});

function tokenizeQuery(q) {
  return String(q || "")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t && t.length > 1 && !SEARCH_STOPWORDS.has(t));
}

// Map words a user might say to the grain a report covers.
const PERIOD_HINTS = {
  daily: "daily", day: "daily", today: "daily", yesterday: "daily",
  monthly: "monthly", month: "monthly",
  periodically: "range", periodic: "range", range: "range",
  between: "range", from: "range", weekly: "range", week: "range",
};

/**
 * Score every report against a natural-language query and return the top `limit`
 * matches (default 6). Keeps the LLM's tool schema tiny: instead of embedding all
 * 130+ reports in get_report's description, the model calls find_reports first.
 *
 * Returns: [{ key, label, input, description, score }]
 */
export function searchReports(query, limit = 6) {
  const tokens = tokenizeQuery(query);
  // Detect a requested grain (daily/monthly/range) to gently bias ties.
  let wantPeriod = null;
  for (const w of String(query || "").toLowerCase().split(/[^a-z0-9]+/)) {
    if (PERIOD_HINTS[w]) { wantPeriod = PERIOD_HINTS[w]; break; }
  }

  const scored = SEARCH_INDEX.map((e) => {
    let score = 0;
    for (const t of tokens) {
      if (e.strong.has(t)) score += 3;
      else if (e.weak.has(t)) score += 1;
      else {
        // partial / substring match (e.g. "teller" vs "tellers", "perf" vs "performance")
        for (const w of e.strong) { if (w.includes(t) || t.includes(w)) { score += 1.5; break; } }
      }
    }
    if (wantPeriod && e.period === wantPeriod) score += 1.5;
    return { e, score };
  });

  return scored
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score || a.e.key.localeCompare(b.e.key))
    .slice(0, Math.max(1, limit))
    .map(({ e, score }) => ({
      key: e.key,
      label: e.label,
      input: inputFor(REPORTS[e.key]),
      description: e.description,
      score: Math.round(score * 10) / 10,
    }));
}

/** Parse a counter spec like "1,3,5" or "1-15" or "1-5,8" into a sorted number[]. */
export function parseCounters(spec) {
  if (!spec) return [];
  const out = [];
  for (const tok of String(spec).split(",")) {
    const part = tok.trim();
    if (!part) continue;
    const range = part.match(/^(\d+)\s*-\s*(\d+)$/);
    if (range) {
      let a = +range[1];
      let b = +range[2];
      if (a > b) [a, b] = [b, a];
      for (let i = a; i <= b && i - a < 1000; i++) out.push(i);
    } else if (/^\d+$/.test(part)) {
      out.push(+part);
    }
    // ignore invalid tokens
  }
  return [...new Set(out)].sort((x, y) => x - y);
}

// Optional install default for per-counter reports, e.g. QMS_COUNTERS="1-15".
export const DEFAULT_COUNTERS = parseCounters(process.env.QMS_COUNTERS || "");

/** Portable HTTP request (built-in http/https — no global fetch dependency). */
export function request(urlStr, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const lib = u.protocol === "https:" ? https : http;
    const data = body ? Buffer.from(body) : null;
    const opts = {
      method,
      hostname: u.hostname,
      port: u.port || (u.protocol === "https:" ? 443 : 80),
      path: u.pathname + u.search,
      headers: { ...headers, ...(data ? { "Content-Length": data.length } : {}) },
    };
    const req = lib.request(opts, (res) => {
      let chunks = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (chunks += c));
      res.on("end", () =>
        resolve({
          status: res.statusCode,
          headers: res.headers,
          setCookies: res.headers["set-cookie"] || [],
          text: chunks,
        })
      );
    });
    req.on("error", reject);
    req.setTimeout(30000, () => req.destroy(new Error("request timeout")));
    if (data) req.write(data);
    req.end();
  });
}

/** Merge Set-Cookie headers into a single Cookie header, keeping ALL cookies.
 *  Applies in order; later non-empty values overwrite earlier ones. */
export function buildCookieHeader(setCookies) {
  const jar = {};
  for (const sc of setCookies) {
    const pair = sc.split(";")[0];
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (!name) continue;
    if (value) jar[name] = value; // ignore empty (clear) values; keep last real one
  }
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");
}

export function scrapeCsrf(html) {
  const patterns = [
    /name=["']csrf-token["'][^>]*value=["']([^"']+)["']/i,
    /value=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
    /<meta[^>]*name=["']csrf-token["'][^>]*content=["']([^"']+)["']/i,
    /["']?csrf-token["']?\s*[:=]\s*["']([A-Za-z0-9]{20,})["']/i,
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m) return m[1];
  }
  return "";
}

export class Session {
  constructor() {
    this.cookie = "";
    this.csrf = "";
  }

  get isValid() {
    return Boolean(this.cookie);
  }

  async login() {
    if (!USER || !HASH_PWD) {
      throw new Error("QMS_USER and QMS_HASH_PWD (or QMS_PASS) env vars are required.");
    }
    const body = new URLSearchParams({
      txtUsrId: USER,
      txtPwd: "",
      hashPwd: HASH_PWD,
      randomNum: "0",
      mod: "",
      urlRedirect: "",
    }).toString();
    const resp = await request(BASE_URL + LOGIN_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    this.cookie = buildCookieHeader(resp.setCookies);
    if (!this.cookie) {
      throw new Error("login failed: no session cookie (check QMS_USER / QMS_HASH_PWD).");
    }
    // csrf-token may be in the login response, or on a separate report page.
    this.csrf = scrapeCsrf(resp.text || "");
    if (!this.csrf && REPORT_PAGE_PATH) {
      const page = await request(BASE_URL + REPORT_PAGE_PATH, {
        method: "GET",
        headers: { Cookie: this.cookie },
      });
      this.csrf = scrapeCsrf(page.text || "");
    }
    return this;
  }

  async ensure() {
    if (!this.isValid) await this.login();
    return this;
  }
}

/** Set the date field(s) on a parsed body according to the report's period. */
function setPeriodFields(p, report, args) {
  if (report.period === "monthly") {
    const [yr, mth] = String(args.period).split("-");
    p.set("rptMth", mth || "");
    p.set("rptYr", yr || "");
  } else if (report.period === "range") {
    p.set("rptfrmDt", args.from);
    p.set("rpttoDt", args.to);
  } else {
    p.set("rptDt", args.period);
  }
}

/** Build the form body. `args` is { period } for daily (YYYY-MM-DD) / monthly
 *  (YYYY-MM), or { from, to } (YYYY-MM-DD each) for range reports.
 *
 *  If the report defines its own `payload` (a captured form string), that is used
 *  verbatim and only csrf-token, hRptOut and the date are overridden — the report
 *  already carries all its structural fields (service filters, flags, etc.).
 *  Otherwise the shared PAYLOAD_TEMPLATE is used and the report's identifiers are
 *  applied. */
export function buildBody(report, args, csrf) {
  if (report.payload) {
    const p = new URLSearchParams(report.payload);
    p.set("csrf-token", csrf || "");
    p.set("hRptOut", "csv");
    setPeriodFields(p, report, args);
    // Per-counter reports: counters can't be select-all'd, so inject the chosen ids.
    if (report.counters && Array.isArray(args.counters) && args.counters.length) {
      p.set("hSelCounter", args.counters.join(","));
      for (const n of args.counters) p.set(`Counter ${n}`, String(n));
    }
    return p.toString();
  }

  const p = new URLSearchParams(PAYLOAD_TEMPLATE);
  p.set("csrf-token", csrf || "");
  p.set("hRptOut", "csv");
  p.set("hRptId", report.hRptId);
  p.set("hRptType", report.hRptType);
  p.set("hRptClassId", report.hRptClassId);
  p.set("hLoad1stRecId", report.hLoad1stRecId);
  p.set("hLoad1stRecNm", report.hLoad1stRecNm);
  if (report.period === "monthly") {
    p.delete("rptDt");
    p.set("rptLevel", "");
    p.set("rptSelFieldIdList", "");
  } else if (report.period === "range") {
    p.delete("rptDt");
    p.delete("rptMth");
    p.set("rptYr", "");
    p.set("rptLevel", "");
    p.set("rptSelFieldIdList", "");
  } else {
    p.delete("rptMth");
    p.set("rptYr", "");
    p.set("rptLevel", "1");
    p.set("rptSelFieldIdList", "0");
  }
  setPeriodFields(p, report, args);
  return p.toString();
}

/** Low-level report POST. Returns the raw response details. */
export async function postReportRaw(session, report, args) {
  // Most reports POST to CGenerateReport; some (e.g. Log reports) override `path`.
  const resp = await request(BASE_URL + (report.path || REPORT_PATH), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: session.cookie },
    body: buildBody(report, args, session.csrf),
  });
  const ctype = (resp.headers["content-type"] || "").toLowerCase();
  const text = resp.text;
  const isRedirect = resp.status >= 300 && resp.status < 400;
  const looksLikeLogin = isRedirect || ctype.includes("text/html") || text.trimStart().startsWith("<");
  const ok = resp.status >= 200 && resp.status < 400;
  return { ok, status: resp.status, ctype, text, looksLikeLogin };
}

// Module-level session reused across MCP calls.
const session = new Session();

/** High-level: ensure login, fetch + parse the report, retry once on expiry. */
export async function fetchReport(report, args) {
  await session.ensure();
  let r = await postReportRaw(session, report, args);
  if (r.looksLikeLogin) {
    session.cookie = "";
    await session.login();
    r = await postReportRaw(session, report, args);
  }
  if (!r.ok) return { error: "http_error", status: r.status, body_preview: r.text.slice(0, 300) };
  if (r.looksLikeLogin) {
    return { error: "session_expired", message: "Got HTML after re-login — csrf may be required or params invalid." };
  }
  const period = report.period === "range" ? `${args.from}..${args.to}` : args.period;
  return { report: report.label, period, ...condense(r.text) };
}

export function parseCSV(text) {
  const rows = [];
  let field = "";
  let row = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
    else if (c !== "\r") field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((c) => c !== ""));
}

export function condense(csvText) {
  const rows = parseCSV(csvText);
  if (rows.length === 0) return { columns: [], row_count: 0, rows: [] };
  const columns = rows[0];
  const dataRows = rows.slice(1);
  const capped = dataRows.slice(0, MAX_ROWS).map((r) => {
    const obj = {};
    columns.forEach((col, idx) => { obj[col || `col${idx}`] = r[idx] ?? ""; });
    return obj;
  });
  return {
    columns,
    row_count: dataRows.length,
    returned: capped.length,
    truncated: dataRows.length > MAX_ROWS,
    rows: capped,
  };
}
