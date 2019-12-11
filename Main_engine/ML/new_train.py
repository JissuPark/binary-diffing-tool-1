# coding:utf-8

import pandas as pd
import numpy as np
import pickle
import sklearn.ensemble as ske
from sklearn.model_selection import train_test_split
from sklearn import tree
from sklearn.feature_selection import SelectFromModel
import os
from sklearn.externals import joblib
from sklearn.naive_bayes import GaussianNB
import tensorflow as tf
from sklearn.metrics import confusion_matrix
import json
from xgboost import XGBClassifier
import xgboost as xgb
from sklearn.ensemble import VotingClassifier
from sklearn.linear_model import LogisticRegression
from keras.models import Sequential
from keras.layers import Dense
from keras.layers import Dropout
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.ensemble import AdaBoostClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.ensemble import VotingClassifier
import csv
from sklearn.model_selection import GridSearchCV
from lightgbm import LGBMClassifier
from tensorflow import keras
import matplotlib.pyplot as plt
from sklearn.datasets import load_breast_cancer
import pandas_profiling as pp  # pip install pandas_profiling
from multiprocessing import Process, current_process, Queue, Pool
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import OneHotEncoder
import datetime
from logging import handlers

import logging

##############################################################################
result_csv_file_path = "D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\ML\\2019_11_03_09_37_22_outfile.csv"
result_csv = "D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\ML\\" + datetime.datetime.now().strftime(
    "%Y_%m_%d_%H_%M_%S") + "_out_train.csv"
logfile="./logfile.txt"
'''
df=pd.read_csv(result_csv_file_path)
profile = df.profile_report (title = 'profile anaylsyis')
profile.to_file (outputfile = "D:\\Allinone\\\CyberBigDataStudy\\profiling.html")
'''


##############################################################################
#log settings2017_2018_labels
carLogFormatter = logging.Formatter('%(asctime)s,%(message)s')

#handler settings
carLogHandler = handlers.TimedRotatingFileHandler(filename=logfile, interval=1, encoding='utf-8')
carLogHandler.setFormatter(carLogFormatter)
carLogHandler.suffix = "%Y%m%d"

#logger set
carLogger = logging.getLogger()
carLogger.setLevel(logging.INFO)
carLogger.addHandler(carLogHandler)

#use logger
carLogger.info("car is coming")

##############################################################################
data = pd.read_csv(result_csv_file_path, sep=',')
data = data.dropna()
# Filname이랑 ismalware 항목 모두 지운 값이 x
X = data.drop(['label'], axis=1).values
y = data['label'].values
'''
carLogger.info('Researching important feature based on %i total features\n' % X.shape[1])
# Trees Classifier를 위한 feature 설정
fsel = ske.ExtraTreesClassifier().fit(X, y)
model = SelectFromModel(fsel, prefit=True)
X_new = model.transform(X)
nb_features = X_new.shape[1]
print(nb_features )
'''
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1 )


##############################################################################


#
##############################################################################
def GridSearchCV_Function(object_type_flag):
    if object_type_flag == 1:
        xgb_type = 'binary:logistic'
        lgb_type = 'binary'
    elif object_type_flag == 0:
        xgb_type = 'multi:softprob'
        lgb_type = 'multi:softprob'

    param_dist_xgb = {
        "booster": ['gbtree'],
        "silent": [1],
        "learning_rate": [0.15, 0.2, 0.25, 0.3],
        "max_depth": [6, 10, 15, 20],
        "n_estimators": [2000, 2500],
        "objective": [xgb_type]
    }

    param_dist_lgb = {
        "verbosity": [0],
        "boosting_type": ['gbdt'],  # default gbdt
        "max_bin": [127, 255],
        "num_leaves": [31, 47, 64, 128],
        "random_state": [501],
        "learning_rate": [0.15, 0.2, 0.25, 0.3],
        "n_estimators": [2000, 2500],
        "objective": [lgb_type]
    }

    ClfXGB = GridSearchCV(XGBClassifier(),
                          param_grid=param_dist_xgb,
                          cv=3,
                          verbose=1,
                          n_jobs=-1)
    ClfLGB = GridSearchCV(LGBMClassifier(),
                          param_grid=param_dist_lgb,
                          cv=3,
                          verbose=-1,
                          n_jobs=-1)
    XGB_Fit = ClfXGB.fit(X_train, y_train)
    LGB_Fit = ClfLGB.fit(X_train, y_train)
    carLogger.info(XGB_Fit)
    carLogger.info(LGB_Fit)
    xgb = XGB_Fit.predict(X_test)
    lgb = LGB_Fit.predict(X_test)

    return xgb, lgb


def Label_calc():
    xgb_probability, lgb_probability = GridSearchCV_Function(1)
    xgb_predictions, lgb_predictions = GridSearchCV_Function(0)

    xgb_predictions = [pre if int(pre) == 1 else -1 for pre in xgb_predictions]
    lgb_predictions = [pre if int(pre) == 1 else -1 for pre in lgb_predictions]

    Calc_Y = []
    for index in range(len(xgb_probability)):
        Yscore = (xgb_predictions[index] * xgb_probability[index]) + (lgb_predictions[index] * lgb_probability[index])
        if Yscore > 0:
            Yscore = 1.
        else:
            Yscore = 0.
        Calc_Y.append(Yscore)

    print(100.0 * accuracy_score(y_test, Calc_Y))


##############################################################################


def trains_ML():
    with open(result_csv, 'w+', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow(['RandomForestClassifier_classifier', 'GradientBoostingClassifier_classifier',
                         'XGBClassifier_classifiers', 'LGBMClassifier','SVC','ensemble'])


        param_dist_RF = {
            "n_estimators":[200,250,300],
            "bootstrap":[False,True],
            "warm_start":[False,True],
            "min_samples_leaf":[1,5,10],
            "random_state": [501,1000,2000,2500],
            "oob_score":[False,True]
        }
        RF = GridSearchCV(RandomForestClassifier(),
                              param_grid=param_dist_RF,
                              cv=5,
                              verbose=1,
                              n_jobs=-1)

        param_dist_GB = {
            "n_estimators":[2200,2500],
            "bootstrap":[False,True],
            "warm_start":[False,True],
            "max_features":[None,100,150,175,200],
            "min_samples_leaf":[1,5,10],
            "min_samples_split ":[1,2,5,10,20],
            "random_state": [501,1000,2000,2500],
            "n_iter_no_change":[None,200,500,1000],
        }
        GB = GridSearchCV(GradientBoostingClassifier(),
                              param_grid=param_dist_GB,
                              cv=5,
                              verbose=1,
                              n_jobs=-1)

        param_dist_xgb = {
            "booster": ['gbtree','gblinear'],
            "[num_class]":[2],
            "verbosity":[0,1,2],
            "learning_rate": [0.15, 0.2, 0.25, 0.3],
            "max_depth": [6, 10, 15, 20,30],
            "n_estimators": [1500,2000, 2500],
            "subsample":[0.5,0.2,1],
            "tree_method":['auto','exact','hist','exact']
        }
        XGB = GridSearchCV(XGBClassifier(),
                              param_grid=param_dist_xgb,
                              cv=5,
                              verbose=5,
                              n_jobs=-1)

        param_dist_lgb = {
            "verbosity": [0],
            "boosting_type": ['gbdt'],  # default gbdt
            "max_bin": [127, 255],
            "num_leaves": [31, 47, 64, 128],
            "random_state": [501],
            "learning_rate": [0.15, 0.2, 0.25, 0.3],
            "n_estimators": [2000, 2500],
        }
        LGB = GridSearchCV(LGBMClassifier(),
                              param_grid=param_dist_lgb,
                              cv=5,
                              verbose=5,
                              n_jobs=-1)


        param_dist_svc= {
            "max_iter":[-1,5,10],
            "random_state": [501,1000]
        }
        svc = GridSearchCV(SVC(),
                              param_grid=param_dist_svc,
                              cv=5,
                              verbose=5,
                              n_jobs=-1)


        RF_Fit = RF.fit(X_train, y_train)
        GB_Fit = GB.fit(X_train, y_train)
        XGB_Fit = XGB.fit(X_train, y_train)
        LGB_Fit = LGB.fit(X_train, y_train)
        svc_Fit =svc.fit(X_train, y_train)

        carLogger.info(RF_Fit)
        carLogger.info(GB_Fit)
        carLogger.info(XGB_Fit)
        carLogger.info(LGB_Fit)

        y_list = []
        for y_fre in y_test:
            if y_fre >1:y_list.append(1)
            else:y_fre.append(y_list)

        rf_predict= RF_Fit.predict(X_test)
        rf_list=[]
        for rf_fre in rf_predict:
            if rf_fre >1:rf_list.append(1)
            else:rf_list.append(rf_fre)

        rf_accuracy = 100.0 * accuracy_score(y_list, rf_list)
        print("accuracy : {}".format(rf_accuracy))
        writer.writerow([rf_accuracy])
        carLogger.info(rf_accuracy)

        gb_predict= GB_Fit.predict(X_test)
        gb_list=[]
        for gb_fre in gb_predict:
            if gb_fre >1:gb_list.append(1)
            else:gb_list.append(gb_fre)

        gb_accuracy = 100.0 * accuracy_score(y_list, gb_list)
        print("accuracy : {}".format(gb_accuracy))
        writer.writerow([gb_accuracy])
        carLogger.info(gb_accuracy)

        xgb_predict= XGB_Fit.predict(X_test)
        xgb_list=[]
        for xgb_fre in xgb_predict:
            if xgb_fre >1:xgb_list.append(1)
            else:xgb_list.append(xgb_fre)

        xgb_accuracy = 100.0 * accuracy_score(y_list, xgb_list)
        print("accuracy : {}".format(xgb_accuracy))
        writer.writerow([xgb_accuracy])
        carLogger.info(xgb_accuracy)

        lgb_predict= LGB_Fit.predict(X_test)
        lgb_list=[]
        for lgb_fre in lgb_predict:
            if lgb_fre >1:lgb_list.append(1)
            else:lgb_list.append(lgb_fre)

        lgb_accuracy = 100.0 * accuracy_score(y_list, lgb_list)
        print("accuracy : {}".format(lgb_accuracy))
        writer.writerow([lgb_accuracy])
        carLogger.info(lgb_accuracy)


        svc_predict= svc_Fit.predict(X_test)
        svc_list=[]
        for svc_fre in svc_predict:
            if svc_fre >1:svc_list.append(1)
            else:svc_list.append(svc_fre)

        svc_accuracy = 100.0 * accuracy_score(y_list, svc_predict)
        print("accuracy : {}".format(svc_accuracy))
        writer.writerow([svc_accuracy])

        eclf = VotingClassifier(estimators=[('rf', RF), ('gb', GB), ('xgb', XGB),('lgb', LGB)])
        param_dist_ensemble = {
            "voting":["hard","soft"]
        }

        Ensnble = GridSearchCV(estimator=eclf, param_grid=param_dist_ensemble, scoring='accuracy', cv=5,n_jobs=-1,verbose=1)
        Ensnble_Fit = Ensnble.fit(X_train, y_train)
        Ensnble_predict= Ensnble_Fit.predict(X_test)
        ense_list=[]
        for ensem_fre in Ensnble_predict:
            if ensem_fre  >1:ense_list.append(1)
            else:ense_list.append(ensem_fre )

        Ensnble_predict_accuracy = 100.0 * accuracy_score(y_list, ense_list)
        print("accuracy : {}".format(Ensnble_predict_accuracy))
        writer.writerow([Ensnble_predict_accuracy])
        carLogger.info(Ensnble_predict_accuracy)






##############################################################################

def ML_Proba_Predict_Train():



    classifiers1 = RandomForestClassifier(n_estimators=350, n_jobs=-1)
    classifiers2 = GradientBoostingClassifier(n_estimators=2500)
    classifiers3 = xgb.XGBClassifier(n_estimators=2500, objective="binary:logistic", random_state=2500, n_jobs=-1)
    classifiers4 = LGBMClassifier(n_estimators=2500, random_state=2500, n_jobs=-1)

    rf=classifiers1.fit(X_train, y_train)
    joblib.dump(rf , './ML_model2.pkl')
    predictions = rf.predict(X_test)

    #accuracy = 100.0 * accuracy_score(y_test, predictions)
    #print("Ensenble : {} ".format(accuracy))


class ML_jobs_class:
    def __init__(self):
        self.file_path = "D:\\Allinone\\Programing\\Python\\악성코드통합\\R&D_데이터_챌린지_2018\\TestSet\\"
        self.file_full_path_list = [os.path.join(self.file_path, sample) for sample in os.listdir(self.file_path)]

    def ML_JOB(self):
        #테스트할 폴더의 경로를 삽입하면됩니다.

        model = joblib.load('./ML_model2.pkl')
        predict_ml_csv_path = "./predict.csv"
        save_ml_jobs_csv="./predict_result2.csv"
        with open(save_ml_jobs_csv, 'w+', newline='', encoding='utf-8') as csv_file:
            result_csv_writer = csv.writer(csv_file, delimiter=',')

            predict_csv_file_handle= open(predict_ml_csv_path , 'r', encoding='utf-8')
            reader= csv.reader(predict_csv_file_handle)
            for line in reader:

                file_hash=line[0]
                file_features=line[1:]
                try:
                    predict_labels = model.predict([file_features])[0]
                    result_csv_writer.writerow([file_hash,predict_labels])
                except:
                    continue
        predict_csv_file_handle.close()
    #######################################################
def DL():
    #result_csv_file_path1 = "D:\\Allinone\\Programing\\Python\\project\\r_d_challenge\ML\\train.csv"
    ##############################################################################
    data = pd.read_csv(result_csv_file_path, sep=',')
    data = data.dropna()
    features = data.drop(['label'], axis=1).values
    labels = data['label'].values

    x_train=features[0:16000]
    y_train=labels[0:16000]
    x_test=features[16000:]
    y_test=labels[16000:]


    # 3. 모델 구성하기
    model = Sequential()
    model.add(Dense(1024, input_dim=977, init="uniform",activation='relu'))
    model.add(Dense(1024,input_dim=1024,init="uniform", activation='relu'))
    model.add(Dense(2048,input_dim=1024,init="uniform",activation='relu'))
    model.add(Dense(4096,input_dim=2048,init="uniform",activation='relu'))
    model.add(Dense(2048,input_dim=4096,init="uniform",activation='relu'))
    model.add(Dense(1024,input_dim=2048,init="uniform",activation='relu'))
    model.add(Dropout(0.25))
    model.add(Dense(512,input_dim=1024,init="uniform",activation='relu'))
    model.add(Dense(256,input_dim=512,init="uniform",activation='relu'))
    model.add(Dense(128,input_dim=256,init="uniform",activation='relu'))
    model.add(Dropout(0.25))
    model.add(Dense(64,input_dim=128,init="uniform",activation='relu'))
    model.add(Dense(32,input_dim=64,init="uniform",activation='relu'))
    model.add(Dense(16,input_dim=32,init="uniform",activation='relu'))
    model.add(Dropout(0.25))
    model.add(Dense(8,input_dim=16,init="uniform",activation='relu'))
    model.add(Dense(1,input_dim=8, init="uniform",activation='sigmoid'))

    # 4. 모델 학습과정 설정하기
    model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])


    # 5. 모델 학습시키기
    model.fit(x_train, y_train, epochs=1500, batch_size=1, validation_split = 0.2)

    # 6. 모델 평가하기
    scores = model.evaluate(x_test, y_test)
    print("%s: %.2f%%" % (model.metrics_names[1], scores[1] * 100))

    return

if __name__ == "__main__":
    #ML_Proba_Predict_Train()
    jobs_class=ML_jobs_class()
    jobs_class.ML_JOB()

    #Label_calc()
    #trains_ML()
