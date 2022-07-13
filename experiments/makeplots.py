import numpy as np
import pandas as pd
import re
import matplotlib.pyplot as plt
import math
import random
import warnings

itec=100
cln=np.array([1, 2, 5, 10, 15, 20])
resarrc = {}
resarrs = {}
tlc=0

#-----------------------------------------------------------------------
#----------------------------Capture Client Side------------------------
#-----------------------------------------------------------------------

for i in range(0, len(cln)):

    dataarr = np.zeros((itec,cln[i]))
    pathbase="logs/clientSide/clientc"
    clientvar=str(cln[i])
    clientapp="/iter"

    for j in range(1, itec):
        itervar=str(j)
        iterapp="/xrfc"
        for k in range(0, cln[i]):
            xrfcvar=str(k+1)
            xrfcapp=".txt"
            finalpath=pathbase+clientvar+clientapp+itervar+iterapp+xrfcvar+xrfcapp
            #print(finalpath)
            try:
                data=np.loadtxt(finalpath, dtype=float)[1]
                #print(data)
                dataarr[j,k] = data
            except:
                #print("Iteration client count is missing");
                tlc+=1
                continue

    resarrc[i] = dataarr

datam = np.zeros(( len(cln) ))
datae = np.zeros(( len(cln) ))
dataeb = np.zeros((2, len(cln) ))

warnings.filterwarnings("ignore")
for arr in resarrc:
    #print(arr)
    datat = (resarrc[arr])
    datat[datat == 0] = np.nan
    itemeans = np.nanmean(datat, axis=0)
    fmeans = np.nanmean(itemeans)
    datam[arr] = fmeans
    itemeans = itemeans[~np.isnan(itemeans)]
    dataeb[0,arr] = np.max(itemeans) - fmeans
    dataeb[1,arr] = np.min(itemeans) - fmeans
    ferr = np.std(itemeans)/np.sqrt(len(itemeans))
    datae[arr] = ferr


#-----------------------------------------------------------------------
#----------------------------Capture Server Side------------------------
#-----------------------------------------------------------------------
tls=0
for i in range(0, len(cln)):

    dataarr = np.zeros((itec))
    pathbase="logs/serverSide/clientc"
    clientvar=str(cln[i])
    clientapp="/iter"

    for j in range(1, itec):
        itervar=str(j)
        iterapp="/xrfslog.txt"
        finalpath=pathbase+clientvar+clientapp+itervar+iterapp
        #print(finalpath)
        try:
            data=np.loadtxt(finalpath, dtype=float)
            #print(data)
            dataarr[j] = cln[i]/data*1000
        except:
            #print("Iteration client count is missing");
            tls+=1
            continue

    resarrs[i] = dataarr

datams = np.zeros(( len(cln) ))
dataes = np.zeros(( len(cln) ))
dataebs = np.zeros((2, len(cln) ))

warnings.filterwarnings("ignore")
for arr in resarrs:
    #print(arr)
    datat = (resarrs[arr])
    datat[datat == 0] = np.nan
    fmeans = np.nanmean(datat)
    datams[arr] = fmeans
    datat = datat[~np.isnan(datat)]
    dataebs[0,arr] = np.max(datat) - fmeans
    dataebs[1,arr] = np.min(datat) - fmeans
    ferr = np.std(datat)/np.sqrt(len(datat))
    dataes[arr] = ferr

#-----------------------------------------------------------------------
#-----------------------------Start Plotting----------------------------
#-----------------------------------------------------------------------
markerplace=1

plt.rc('xtick', labelsize=16)
plt.rc('ytick', labelsize=16)

fig1 = plt.figure(figsize=(12,5.1))
ax1 = fig1.add_subplot(111)
ax2 = ax1.twinx()
ax1.plot(cln, datam, 'g-', label="client", marker='*', markevery=markerplace)
(_, caps, _) = ax1.errorbar(cln, datam, yerr=datae, fmt='none', color='g', markersize=8, capsize=10)
ax2.plot(cln, datams , 'b-', label="server", marker='x', markevery=markerplace)
(_, caps, _) = ax2.errorbar(cln, datams, yerr=dataes, fmt='none', color='b', markersize=8, capsize=10)

for cap in caps:
    cap.set_markeredgewidth(1)

ax1.grid()
ax2.grid()

ax1.set_xlabel('Number of Concurrent Clients', fontsize=18)
ax1.set_ylabel('Average client latency (ms)', fontsize=18)
ax2.set_ylabel('Average server throughput (users/s)', fontsize=18)
#fig1.legend(['Client-side', 'Server-side'], bbox_to_anchor=(0.4, 0.88), fontsize=14)
fig1.legend(bbox_to_anchor=(0.25, 0.88), fontsize=14)

plt.savefig('figures/tot_lat_thr.eps', format='eps')
