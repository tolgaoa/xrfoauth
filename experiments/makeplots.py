import numpy as np
import pandas as pd
import re
import matplotlib.pyplot as plt
import math
import random
import warnings

itec=5
#cln=np.array([1, 2, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
#cln=np.array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
#cln=np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50])
#cln=np.array([2, 5, 10, 20, 30, 40])
cln=np.array([1, 2, 4, 6, 8, 10, 20, 30, 40, 50, 100, 200, 300])
resarrc = {}
resarrs = {}
resarrx = {}

tlc=0

#-----------------------------------------------------------------------
#----------------------------Capture Client Side------------------------
#-----------------------------------------------------------------------

for i in range(0, len(cln)):

    dataarr = np.zeros((itec,cln[i]))
    pathbase="logs/thr20/clientSide/clientc"
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
    #dataeb[0,arr] = np.max(itemeans) - fmeans
    #dataeb[1,arr] = np.min(itemeans) - fmeans
    ferr = np.std(itemeans)/np.sqrt(len(itemeans))
    datae[arr] = ferr


#-----------------------------------------------------------------------
#----------------------------Capture Server Side------------------------
#-----------------------------------------------------------------------
tls=0
for i in range(0, len(cln)):

    dataarr = np.zeros((itec))
    dataarrx = np.zeros((itec))
    pathbase="logs/thr20/serverSide/clientc"
    clientvar=str(cln[i])
    clientapp="/iter"

    for j in range(1, itec):
        itervar=str(j)
        iterapp="/xrfslog.txt"
        iterappx="/ctxts.txt"
        finalpath=pathbase+clientvar+clientapp+itervar+iterapp
        finalpathx=pathbase+clientvar+clientapp+itervar+iterappx
        #print(finalpath)
        try:
            data=np.loadtxt(finalpath, dtype=float)
            datax=np.loadtxt(finalpathx, dtype=float)[0]+np.loadtxt(finalpathx, dtype=float)[1]
            #print(data)
            dataarr[j] = cln[i]/data*1000
            dataarrx[j] = datax*cln[i]
        except:
            #print("Iteration client count is missing");
            tls+=1
            continue

    resarrs[i] = dataarr
    resarrx[i] = dataarrx

datams = np.zeros(( len(cln) ))
datamx = np.zeros(( len(cln) ))
dataes = np.zeros(( len(cln) ))
dataex = np.zeros(( len(cln) ))

warnings.filterwarnings("ignore")
for arr in resarrs:
    #print(arr)
    datat = (resarrs[arr])
    datax = (resarrx[arr])
    datat[datat == 0] = np.nan
    datax[datax == 0] = np.nan
    fmeans = np.nanmean(datat)
    fmeansx = np.nanmean(datax)
    datams[arr] = fmeans
    datamx[arr] = fmeansx
    datat = datat[~np.isnan(datat)]
    datax = datax[~np.isnan(datax)]
    ferr = np.std(datat)/np.sqrt(len(datat))
    ferrx = np.std(datax)/np.sqrt(len(datax))
    dataes[arr] = ferr
    dataex[arr] = ferrx

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

ax1.tick_params(axis='y', colors='green')
ax2.tick_params(axis='y', colors='blue')
ax1.yaxis.label.set_color('green')
ax2.yaxis.label.set_color('blue')

ax1.set_xlabel('Number of Concurrent Clients', fontsize=18)
ax1.set_ylabel('Average client latency (ms)', fontsize=18)
ax2.set_ylabel('Average server throughput (users/s)', fontsize=18)
#fig1.legend(['Client-side', 'Server-side'], bbox_to_anchor=(0.4, 0.88), fontsize=14)
fig1.legend(bbox_to_anchor=(0.45, 0.88), fontsize=14)

plt.savefig('figures/tot_lat_thr.eps', format='eps')
#-------------------------------------------------------------------------
#-------------------------------------------------------------------------
fig2 = plt.figure(figsize=(12,5.1))
ax3 = fig2.add_subplot(111)
ax4 = ax3.twinx()
ax3.plot(cln, datamx, 'g-', label="client", marker='*', markevery=markerplace)
(_, caps, _) = ax1.errorbar(cln, datamx, yerr=datae, fmt='none', color='g', markersize=8, capsize=10)
ax4.plot(cln, datams , 'b-', label="server", marker='x', markevery=markerplace)
(_, caps, _) = ax2.errorbar(cln, datams, yerr=dataes, fmt='none', color='b', markersize=8, capsize=10)

for cap in caps:
    cap.set_markeredgewidth(1)

ax3.grid()
ax4.grid()

ax3.tick_params(axis='y', colors='green')
ax4.tick_params(axis='y', colors='blue')
ax3.yaxis.label.set_color('green')
ax4.yaxis.label.set_color('blue')

ax3.set_xlabel('Number of Concurrent Clients', fontsize=18)
ax3.set_ylabel('Server process context switches', fontsize=18)
ax4.set_ylabel('Average server throughput (users/s)', fontsize=18)
#fig1.legend(['Client-side', 'Server-side'], bbox_to_anchor=(0.4, 0.88), fontsize=14)
fig2.legend(bbox_to_anchor=(0.45, 0.88), fontsize=14)

plt.savefig('figures/tot_ctx_thr.eps', format='eps')
