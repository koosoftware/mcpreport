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
  const resp = await request(BASE_URL + REPORT_PATH, {
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
