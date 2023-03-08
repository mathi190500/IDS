from flask import Flask, request, render_template
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder,OneHotEncoder
from sklearn import preprocessing
from sklearn.feature_selection import RFE
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split # Import train_test_split function
import warnings
from sklearn.feature_selection import SelectPercentile, f_classif
from sklearn.feature_selection import RFE
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn import metrics
warnings.filterwarnings("ignore")
app = Flask(__name__)

@app.route("/")
def home():
    return "<p>Home</p>"

@app.route("/upload", methods=['GET','POST'])
def uploadFile():
    if request.method == 'POST':
        f = request.files['raw_data']
        f.save(os.getcwd() + "/testdata/sample.csv")
        print(f)
        col_names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]
        dataset_test= pd.read_csv(os.getcwd()+"/testdata/sample.csv", header=None, names = col_names)
        print(dataset_test.head())
        categorical_columns=['protocol_type', 'service', 'flag'] 
        dataset_test_categorical_values = dataset_test[categorical_columns]
        # protocol type
        unique_protocol=sorted(dataset_test.protocol_type.unique())
        string1 = 'Protocol_type_'
        unique_protocol2=[string1 + x for x in unique_protocol]
        # service
        unique_service=sorted(dataset_test.service.unique())
        string2 = 'service_'
        unique_service2=[string2 + x for x in unique_service]
        # flag
        unique_flag=sorted(dataset_test.flag.unique())
        string3 = 'flag_'
        unique_flag2=[string3 + x for x in unique_flag]
        # put together
        testdumcols=unique_protocol2 + unique_service2 + unique_flag2
        dataset_test_categorical_values_enc=dataset_test_categorical_values.apply(LabelEncoder().fit_transform)
        enc = OneHotEncoder()
        dataset_test_categorical_values_encenc = enc.fit_transform(dataset_test_categorical_values_enc)
        dataset_test_cat_data = pd.DataFrame(dataset_test_categorical_values_encenc.toarray(),columns=testdumcols)
        testservice= dataset_test['service'].tolist()
        difference =['service_http_8001','service_harvest','service_urh_i','service_http_2784','service_red_i','service_aol']   
        for col in difference:
             dataset_test_cat_data[col] = 0
        newdf_test=dataset_test.join(dataset_test_cat_data)
        newdf_test.drop('flag', axis=1, inplace=True)
        newdf_test.drop('protocol_type', axis=1, inplace=True)
        newdf_test.drop('service', axis=1, inplace=True)
        labeldf_test=newdf_test['label']
        newlabeldf_test=labeldf_test.replace({ 'normal' : 0, 'neptune' : 1 ,'back': 1, 'land': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,'mailbomb': 1, 'apache2': 1, 'processtable': 1, 'udpstorm': 1, 'worm': 1,
                           'ipsweep' : 2,'nmap' : 2,'portsweep' : 2,'satan' : 2,'mscan' : 2,'saint' : 2
                           ,'ftp_write': 3,'guess_passwd': 3,'imap': 3,'multihop': 3,'phf': 3,'spy': 3,'warezclient': 3,'warezmaster': 3,'sendmail': 3,'named': 3,'snmpgetattack': 3,'snmpguess': 3,'xlock': 3,'xsnoop': 3,'httptunnel': 3,
                           'buffer_overflow': 4,'loadmodule': 4,'perl': 4,'rootkit': 4,'ps': 4,'sqlattack': 4,'xterm': 4})
        # put the new label column back
        newdf_test['label'] = newlabeldf_test
        to_drop_DoS = [2,3,4]
        to_drop_Probe = [1,3,4]
        to_drop_R2L = [1,2,4]
        to_drop_U2R = [1,2,3]
        DoS_df_test=newdf_test[~newdf_test['label'].isin(to_drop_DoS)];
        Probe_df_test=newdf_test[~newdf_test['label'].isin(to_drop_Probe)];
        R2L_df_test=newdf_test[~newdf_test['label'].isin(to_drop_R2L)];
        U2R_df_test=newdf_test[~newdf_test['label'].isin(to_drop_U2R)];
        X_DoS_test = DoS_df_test.drop('label',1)
        Y_DoS_test = DoS_df_test.label
        X_Probe_test = Probe_df_test.drop('label',1)
        Y_Probe_test = Probe_df_test.label
        X_R2L_test = R2L_df_test.drop('label',1)
        Y_R2L_test = R2L_df_test.label
        X_U2R_test = U2R_df_test.drop('label',1)
        Y_U2R_test = U2R_df_test.label
        colNames=list(X_DoS_test)
        scaler5 = preprocessing.StandardScaler().fit(X_DoS_test)
        X_DoS_test=scaler5.transform(X_DoS_test) 
        scaler6 = preprocessing.StandardScaler().fit(X_Probe_test)
        X_Probe_test=scaler6.transform(X_Probe_test) 
        scaler7 = preprocessing.StandardScaler().fit(X_R2L_test)
        X_R2L_test=scaler7.transform(X_R2L_test) 
        scaler8 = preprocessing.StandardScaler().fit(X_U2R_test)
        X_U2R_test=scaler8.transform(X_U2R_test)
        X_DoS_test.std(axis=0)
        X_Probe_test.std(axis=0)
        X_R2L_test.std(axis=0)
        X_U2R_test.std(axis=0)
        np.seterr(divide='ignore', invalid='ignore');
        selector=SelectPercentile(f_classif, percentile=10)
        X_newDoS = selector.fit_transform(X_DoS_test,Y_DoS_test)
        true=selector.get_support()
        newcolindex_DoS=[i for i, x in enumerate(true) if x]
        newcolname_DoS=list(colNames[i] for i in newcolindex_DoS)
        X_newProbe = selector.fit_transform(X_Probe_test,Y_Probe_test)
        true=selector.get_support()
        newcolindex_Probe=[i for i, x in enumerate(true) if x]
        newcolname_Probe=list(colNames[i] for i in newcolindex_Probe)
        X_newR2L = selector.fit_transform(X_R2L_test,Y_R2L_test)
        true=selector.get_support()
        newcolindex_R2L=[i for i, x in enumerate(true) if x]
        newcolname_R2L=list(colNames[i] for i in newcolindex_R2L)
        X_newU2R = selector.fit_transform(X_U2R_test,Y_U2R_test)
        true=selector.get_support()
        newcolindex_U2R=[i for i, x in enumerate(true) if x]
        newcolname_U2R=list(colNames[i] for i in newcolindex_U2R)
        '''clf = DecisionTreeClassifier(random_state=0)

        #  rank all features, i.e continue the elimination until the last one
        rfe = RFE(clf, n_features_to_select=1)
        rfe.fit(X_newDoS, Y_DoS_test.astype('int'))
        rfe.fit(X_newProbe, Y_Probe_test.astype(int))
        rfe.fit(X_newR2L, Y_R2L_test.astype(int))
        rfe.fit(X_newU2R, Y_U2R_test.astype(int))
        clf = DecisionTreeClassifier(random_state=0)
        rfe = RFE(estimator=clf, n_features_to_select=13, step=1)
        rfe.fit(X_DoS_test, Y_DoS_test.astype(int))
        X_rfeDoS=rfe.transform(X_DoS_test)
        true=rfe.support_
        rfecolindex_DoS=[i for i, x in enumerate(true) if x]
        rfecolname_DoS=list(colNames[i] for i in rfecolindex_DoS)
        rfe.fit(X_Probe_test, Y_Probe_test.astype(int))
        X_rfeProbe=rfe.transform(X_Probe_test)
        true=rfe.support_
        rfecolindex_Probe=[i for i, x in enumerate(true) if x]
        rfecolname_Probe=list(colNames[i] for i in rfecolindex_Probe)
        rfe.fit(X_R2L_test, Y_R2L_test.astype(int))
        X_rfeR2L=rfe.transform(X_R2L_test)
        true=rfe.support_
        rfecolindex_R2L=[i for i, x in enumerate(true) if x]
        rfecolname_R2L=list(colNames[i] for i in rfecolindex_R2L)
        rfe.fit(X_U2R_test, Y_U2R_test.astype(int))
        X_rfeU2R=rfe.transform(X_U2R_test)
        true=rfe.support_
        rfecolindex_U2R=[i for i, x in enumerate(true) if x]
        rfecolname_U2R=list(colNames[i] for i in rfecolindex_U2R)
        '''
        clf1 = RandomForestClassifier(n_jobs=2, random_state=0)

        #rank all features, i.e continue the elimination until the last one
        rfe = RFE(clf1, n_features_to_select=1)
        rfe.fit(X_newDoS, Y_DoS_test.astype('int'))
        rfe.fit(X_newProbe, Y_Probe_test.astype(int))
        rfe.fit(X_newR2L, Y_R2L_test.astype(int))
        rfe.fit(X_newU2R, Y_U2R_test.astype(int))
        clf1 = RandomForestClassifier(n_jobs=2, random_state=0)
        rfe = RFE(estimator=clf1, n_features_to_select=13, step=1)
        rfe.fit(X_DoS_test, Y_DoS_test.astype(int))
        '''X_rfeDoS=rfe.transform(X_DoS_test)
        true=rfe.support_
        rfecolindex_DoS=[i for i, x in enumerate(true) if x]
        rfecolname_DoS=list(colNames[i] for i in rfecolindex_DoS)
        rfe.fit(X_Probe_test, Y_Probe_test.astype(int))
        X_rfeProbe=rfe.transform(X_Probe_test)
        true=rfe.support_
        rfecolindex_Probe=[i for i, x in enumerate(true) if x]
        rfecolname_Probe=list(colNames[i] for i in rfecolindex_Probe)
        rfe.fit(X_R2L_test, Y_R2L_test.astype(int))
        X_rfeR2L=rfe.transform(X_R2L_test)
        true=rfe.support_
        rfecolindex_R2L=[i for i, x in enumerate(true) if x]    
        rfecolname_R2L=list(colNames[i] for i in rfecolindex_R2L)
        rfe.fit(X_U2R_test, Y_U2R_test.astype(int))
        X_rfeU2R=rfe.transform(X_U2R_test)
        true=rfe.support_
        rfecolindex_U2R=[i for i, x in enumerate(true) if x]
        rfecolname_U2R=list(colNames[i] for i in rfecolindex_U2R)
        '''
        clf1_DoS=RandomForestClassifier(random_state=0)
        clf1_Probe=RandomForestClassifier(random_state=0)
        clf1_R2L=RandomForestClassifier(random_state=0)
        clf1_U2R=RandomForestClassifier(random_state=0)
        clf1_DoS.fit(X_DoS_test, Y_DoS_test.astype(int))
        clf1_Probe.fit(X_Probe_test, Y_Probe_test.astype(int))
        clf1_R2L.fit(X_R2L_test, Y_R2L_test.astype(int))
        clf1_U2R.fit(X_U2R_test, Y_U2R_test.astype(int))
        clf1_DoS.predict(X_DoS_test)
        Y_DoS_pred1=clf1_DoS.predict(X_DoS_test)
        Y_Probe_pred1=clf1_Probe.predict(X_Probe_test)
        Y_R2L_pred1=clf1_R2L.predict(X_R2L_test)
        Y_U2R_pred1=clf1_U2R.predict(X_U2R_test)
        accuracy1d = cross_val_score(clf1_DoS, X_DoS_test, Y_DoS_test, cv=10, scoring='accuracy')
        #print("Accuracy for DoS: %0.5f (+/- %0.5f)" % (accuracy1d.mean(), accuracy1d.std() * 2))
        accd = accuracy1d.mean()
        precision1d = cross_val_score(clf1_DoS, X_DoS_test, Y_DoS_test, cv=10, scoring='precision')
        pred = precision1d.mean()
        #print("Precision for DoS: %0.5f (+/- %0.5f)" % (precision1d.mean(), precision1d.std() * 2))
        recall1d = cross_val_score(clf1_DoS, X_DoS_test, Y_DoS_test, cv=10, scoring='recall')
        recd = recall1d.mean()
        #print("Recall for DoS: %0.5f (+/- %0.5f)" % (recall1d.mean(), recall1d.std() * 2))
        f1d = cross_val_score(clf1_DoS, X_DoS_test, Y_DoS_test, cv=10, scoring='f1')
        #print("F-measure for DoS: %0.5f (+/- %0.5f)" % (f1d.mean(), f1d.std() * 2))
        fd = f1d.mean()
        accuracy1p = cross_val_score(clf1_Probe, X_Probe_test, Y_Probe_test, cv=10, scoring='accuracy')
        #print("Accuracy for Probe: %0.5f (+/- %0.5f)" % (accuracy1p.mean(), accuracy1p.std() * 2))
        accp = accuracy1p.mean()
        precision1p = cross_val_score(clf1_Probe, X_Probe_test, Y_Probe_test, cv=10, scoring='precision_macro')
        #print("Precision for Probe: %0.5f (+/- %0.5f)" % (precision1p.mean(), precision1p.std() * 2))
        prep = precision1p.mean()
        recall1p = cross_val_score(clf1_Probe, X_Probe_test, Y_Probe_test, cv=10, scoring='recall_macro')
        recp = recall1p.mean()
        #print("Recall for Probe: %0.5f (+/- %0.5f)" % (recall1p.mean(), recall1p.std() * 2))
        f1p = cross_val_score(clf1_Probe, X_Probe_test, Y_Probe_test, cv=10, scoring='f1_macro')
        fp = f1p.mean()
        #print("F-measure for Probe: %0.5f (+/- %0.5f)" % (f1p.mean(), f1p.std() * 2))
        accuracy1r = cross_val_score(clf1_R2L, X_R2L_test, Y_R2L_test, cv=10, scoring='accuracy')
        accr = accuracy1r.mean()
        #print("Accuracy for R2L: %0.5f (+/- %0.5f)" % (accuracy1r.mean(), accuracy1r.std() * 2))
        precision1r = cross_val_score(clf1_R2L, X_R2L_test, Y_R2L_test, cv=10, scoring='precision_macro')
        prer = precision1r.mean()
        #print("Precision for R2L: %0.5f (+/- %0.5f)" % (precision1r.mean(), precision1r.std() * 2))
        recall1r = cross_val_score(clf1_R2L, X_R2L_test, Y_R2L_test, cv=10, scoring='recall_macro')
        recr = recall1r.mean()
        #print("Recall for R2L: %0.5f (+/- %0.5f)" % (recall1r.mean(), recall1r.std() * 2))
        f1r = cross_val_score(clf1_R2L, X_R2L_test, Y_R2L_test, cv=10, scoring='f1_macro')
        fr = f1r.mean()
        #print("F-measure for R2L: %0.5f (+/- %0.5f)" % (f1r.mean(), f1r.std() * 2))
        accuracy1u = cross_val_score(clf1_U2R, X_U2R_test, Y_U2R_test, cv=10, scoring='accuracy')
        #print("Accuracy for U2R: %0.5f (+/- %0.5f)" % (accuracy1u.mean(), accuracy1u.std() * 2))
        accu = accuracy1u.mean()
        precision1u = cross_val_score(clf1_U2R, X_U2R_test, Y_U2R_test, cv=10, scoring='precision_macro')
        preu = precision1u.mean()
        #print("Precision for U2R: %0.5f (+/- %0.5f)" % (precision1u.mean(), precision1u.std() * 2))
        recall1u = cross_val_score(clf1_U2R, X_U2R_test, Y_U2R_test, cv=10, scoring='recall_macro')
        recu = recall1u.mean()
        #print("Recall for U2R: %0.5f (+/- %0.5f)" % (recall1u.mean(), recall1u.std() * 2))
        f1u = cross_val_score(clf1_U2R, X_U2R_test, Y_U2R_test, cv=10, scoring='f1_macro')
        #print("F-measure for U2R: %0.5f (+/- %0.5f)" % (f1u.mean(), f1u.std() * 2))
        fu = f1u.mean()
        print(fu)
        return render_template("display.html",accd = accd, pred = pred, recd = recd, f1d = fd, accp = accp, prep = prep, recp = recp, f1p = fp,accr = accr, prer = prer, recr = recr, f1r = fr,accu = accu, preu = preu, recu = recu, f1u = fu)
    return render_template("index.html")

