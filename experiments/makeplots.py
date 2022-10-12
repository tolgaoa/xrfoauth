import numpy as np
import pandas as pd
import re
import matplotlib.pyplot as plt
import math
import random
import warnings

itec=10
cln=np.array([2, 4, 6, 8, 10, 15, 20, 25, 30, 50, 100, 200, 300, 400, 500])
#cln=np.array([2, 4, 6, 8, 10, 15, 20, 25, 30, 50 ,100, 200, 300, 400, 500])
tln = np.array([2, 6, 12, 20])

tlc=0
tls=0
warnings.filterwarnings("ignore")
#-----------------------------------------------------------------------
#----------------------------Capture Client Side------------------------
#-----------------------------------------------------------------------
resthreadc={}
for t in range(0, len(tln)):
    thrvar=str(tln[t])
    resarrc = {}
    for i in range(0, len(cln)):
        dataarr = np.zeros((itec,cln[i]))
        pathbase="logs/thr"
        paththrd="/clientSide/clientc"
        clientvar=str(cln[i])
        clientapp="/iter"
        for j in range(1, itec):
            itervar=str(j)
            iterapp="/xrfc"
            for k in range(0, cln[i]):
                xrfcvar=str(k+1)
                xrfcapp=".txt"
                finalpath=pathbase+thrvar+paththrd+clientvar+clientapp+itervar+iterapp+xrfcvar+xrfcapp
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
    resthreadc[t] = resarrc

datam = np.zeros(( len(tln), len(cln) ))
datae = np.zeros(( len(tln), len(cln) ))

for t in resthreadc:
    resarrc=resthreadc[t]
    for arr in resarrc:
        datat = (resarrc[arr])
        datat[datat == 0] = np.nan
        itemeans = np.nanmean(datat, axis=0)
        fmeans = np.nanmean(itemeans)
        datam[t,arr] = fmeans
        itemeans = itemeans[~np.isnan(itemeans)]
        ferr = np.std(itemeans)/np.sqrt(len(itemeans))
        datae[t,arr] = ferr


#-----------------------------------------------------------------------
#----------------------------Capture Server Side------------------------
#-----------------------------------------------------------------------
resthreads={}
resthreadx={}

for t in range(0, len(tln)):
    thrvar=str(tln[t])
    resarrs={}
    resarrx={}
    for i in range(0, len(cln)):

        dataarr = np.zeros((itec))
        dataarrx = np.zeros((itec))
        pathbase="logs/thr"
        paththrd="/serverSide/clientc"
        clientvar=str(cln[i])
        clientapp="/iter"

        for j in range(1, itec):
            itervar=str(j)
            iterapp="/xrfslog.txt"
            iterappx="/ctxts.txt"
            finalpath=pathbase+thrvar+paththrd+clientvar+clientapp+itervar+iterapp
            finalpathx=pathbase+thrvar+paththrd+clientvar+clientapp+itervar+iterappx
            #print(finalpath)
            try:
                data=np.loadtxt(finalpath, dtype=float)[1]
                datax=np.loadtxt(finalpathx, dtype=float)
                dataarr[j] = cln[i]/(data-1000)*1000
                dataarrx[j] = np.sum(datax)
            except:
                continue

        resarrs[i] = dataarr
        resarrx[i] = dataarrx
    
    resthreads[t] = resarrs
    resthreadx[t] = resarrx

datams = np.zeros((len(tln), len(cln) ))
datamx = np.zeros((len(tln), len(cln) ))
dataes = np.zeros((len(tln), len(cln) ))
dataex = np.zeros((len(tln), len(cln) ))

for t in resthreads:
    resarrs=resthreads[t]
    resarrx=resthreadx[t]
    for arr in resarrs:
        datat = (resarrs[arr])
        datax = (resarrx[arr])
        datat[datat == 0] = np.nan
        datax[datax == 0] = np.nan
        fmeans = np.nanmean(datat)
        fmeansx = np.nanmean(datax)
        datams[t,arr] = fmeans
        datamx[t,arr] = fmeansx
        datat = datat[~np.isnan(datat)]
        datax = datax[~np.isnan(datax)]
        ferr = np.std(datat)/np.sqrt(len(datat))
        ferrx = np.std(datax)/np.sqrt(len(datax))
        dataes[t,arr] = ferr
        dataex[t,arr] = ferrx

#-----------------------------------------------------------------------
#-----------------------------Start Plotting----------------------------
#-----------------------------------------------------------------------
markerplace=1

plt.rc('xtick', labelsize=16)
plt.rc('ytick', labelsize=16)

fig1 = plt.figure(figsize=(12,5.1))
ax1 = fig1.add_subplot(111)
ax2 = ax1.twinx()
ax1.plot(cln, datam[0,:], 'g-', label="client", marker='*', markevery=markerplace)
(_, caps, _) = ax1.errorbar(cln, datam[0,:], yerr=datae[0,:], fmt='none', color='g', markersize=8, capsize=10)
ax2.plot(cln, datams[0,:] , 'b-', label="server", marker='x', markevery=markerplace)
(_, caps, _) = ax2.errorbar(cln, datams[0,:], yerr=dataes[0,:], fmt='none', color='b', markersize=8, capsize=10)

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
ax3.plot(cln, datamx[0,:], 'g-', label="client", marker='*', markevery=markerplace)
(_, caps, _) = ax1.errorbar(cln, datamx[0,:], yerr=datae[0,:], fmt='none', color='g', markersize=8, capsize=10)
ax4.plot(cln, datams[0,:] , 'b-', label="server", marker='x', markevery=markerplace)
(_, caps, _) = ax2.errorbar(cln, datams[0,:], yerr=dataes[0,:], fmt='none', color='b', markersize=8, capsize=10)

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
fig2.legend(bbox_to_anchor=(0.45, 0.88), fontsize=14)

plt.savefig('figures/tot_ctx_thr.eps', format='eps')
#-------------------------------------------------------------------------
#-------------------------------------------------------------------------
fig3 = plt.figure(figsize=(12,5.1))
plt.plot(cln, datams[0,:], 'g-', label="client", marker='*', markevery=markerplace)
#plt.errorbar(cln, datams[0,:], yerr=dataes[0,:], fmt='none', color='g', markersize=16, capsize=10)
plt.plot(cln, datams[1,:] , 'b-', label="server", marker='x', markevery=markerplace)
#plt.errorbar(cln, datams[1,:], yerr=dataes[1,:], fmt='none', color='b', markersize=16, capsize=10)
plt.plot(cln, datams[2,:] , 'r-', label="server", marker='o', markevery=markerplace)
#plt.errorbar(cln, datams[2,:], yerr=dataes[2,:], fmt='none', color='r', markersize=16, capsize=10)
plt.plot(cln, datams[3,:] , 'k-', label="server", marker='^', markevery=markerplace)
#plt.errorbar(cln, datams[3,:], yerr=dataes[3,:], fmt='none', color='k', markersize=16, capsize=10)


for cap in caps:
    cap.set_markeredgewidth(1)

plt.grid()

plt.xlabel('Number of Concurrent Clients', fontsize=18)
plt.ylabel('Average server throughput (users/s)', fontsize=18)
plt.legend(['thr=2', 'thr=6', 'thr=12', 'thr=20'], bbox_to_anchor=(0.18, 0.88), fontsize=14)

plt.savefig('figures/thr_comp_throu.eps', format='eps')
#-------------------------------------------------------------------------
#-------------------------------------------------------------------------
fig4 = plt.figure(figsize=(12,5.1))
plt.plot(cln, datamx[0,:], 'g-', label="client", marker='*', markevery=markerplace)
plt.errorbar(cln, datamx[0,:], yerr=dataex[0,:], fmt='none', color='g', markersize=16, capsize=10)
plt.plot(cln, datamx[1,:] , 'b-', label="server", marker='x', markevery=markerplace)
plt.errorbar(cln, datamx[1,:], yerr=dataex[1,:], fmt='none', color='b', markersize=16, capsize=10)
plt.plot(cln, datamx[2,:] , 'r-', label="server", marker='o', markevery=markerplace)
plt.errorbar(cln, datamx[2,:], yerr=dataex[2,:], fmt='none', color='r', markersize=16, capsize=10)
plt.plot(cln, datamx[3,:] , 'k-', label="server", marker='^', markevery=markerplace)
plt.errorbar(cln, datamx[3,:], yerr=dataex[3,:], fmt='none', color='k', markersize=16, capsize=10)

for cap in caps:
    cap.set_markeredgewidth(1)

plt.grid()

plt.xlabel('Number of Concurrent Clients', fontsize=18)
plt.ylabel('Average server process context switches', fontsize=18)
plt.legend(['thr=2', 'thr=6', 'thr=12',  'thr=20'], bbox_to_anchor=(0.4, 0.88), fontsize=14)

plt.savefig('figures/thr_comp_ctxt.eps', format='eps')
#-------------------------------------------------------------------------
#-------------------------------------------------------------------------
fig4 = plt.figure(figsize=(12,5.1))
plt.plot(cln, datam[0,:], 'g-', label="client", marker='*', markevery=markerplace)
plt.errorbar(cln, datam[0,:], yerr=datae[0,:], fmt='none', color='g', markersize=16, capsize=10)
plt.plot(cln, datam[1,:] , 'b-', label="server", marker='x', markevery=markerplace)
plt.errorbar(cln, datam[1,:], yerr=datae[1,:], fmt='none', color='b', markersize=16, capsize=10)
plt.plot(cln, datam[2,:] , 'r-', label="server", marker='o', markevery=markerplace)
plt.errorbar(cln, datam[2,:], yerr=datae[2,:], fmt='none', color='r', markersize=16, capsize=10)
plt.plot(cln, datam[3,:] , 'k-', label="server", marker='^', markevery=markerplace)
plt.errorbar(cln, datam[3,:], yerr=datae[3,:], fmt='none', color='k', markersize=16, capsize=10)

for cap in caps:
    cap.set_markeredgewidth(1)

plt.grid()

plt.xlabel('Number of Concurrent Clients', fontsize=18)
plt.ylabel('Average client latency (ms)', fontsize=18)
plt.legend(['thr=2', 'thr=6', 'thr=12',  'thr=20'], bbox_to_anchor=(0.4, 0.88), fontsize=14)

plt.savefig('figures/thr_comp_lat.eps', format='eps')

