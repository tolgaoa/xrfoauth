/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * XRF server side static struct(s)
 *
 * ! file xrf.h
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XRF_SEEN
#define FILE_XRF_SEEN


typedef enum s_type {
	XRF = 0,
	AD = 1,
	LP = 2,
	MC = 3,
	QP = 4,
	QPD = 5,
	TS = 6,
	KPI = 7,
	SSP = 8,
	UNKNOWN = 9
} t_type;

static const std::vector<std::string> type_str = {
	"XRF", "AnomalyDetection", "LoadPrediction", "MeasurementCampaign", "QoEPrediction",
	"QPDriver", "TrafficSteering", "KPIMonitoring", "SignalStormProtection"};

#endif
