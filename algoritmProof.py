import numpy as np
from sklearn.linear_model import LinearRegression
import pandas as pd
from pandas import json_normalize
from sklearn.model_selection import train_test_split
from NVDsearch import NVDdbFilesToJson

# 1. Data Preparation
list_of_cves = NVDdbFilesToJson()  # List of NVD databases from the last three years

# Convert dictionaries to DataFrames
dataframes = []

for cve_dict in list_of_cves:
    df = json_normalize(cve_dict['CVE_Items'])
    dataframes.append(df)


# Combine the DataFrames
combined_data = pd.concat(dataframes)

# Extract relevant parameters
features = ['impact.baseMetricV3.impactScore','impact.baseMetricV2.cvssV2.accessVector', 'impact.baseMetricV2.cvssV2.accessComplexity',
            'impact.baseMetricV2.cvssV2.authentication','impact.baseMetricV2.cvssV2.confidentialityImpact',
            'impact.baseMetricV2.cvssV2.integrityImpact','impact.baseMetricV2.cvssV2.availabilityImpact',
            'impact.baseMetricV2.cvssV2.baseScore','impact.baseMetricV2.severity',
            'impact.baseMetricV2.exploitabilityScore',
            'impact.baseMetricV2.impactScore', 'impact.baseMetricV2.acInsufInfo',
            'impact.baseMetricV2.obtainAllPrivilege', 'impact.baseMetricV2.obtainUserPrivilege',
            'impact.baseMetricV2.obtainOtherPrivilege', 'impact.baseMetricV2.userInteractionRequired']
all_features = ['impact.baseMetricV3.impactScore',
       'impact.baseMetricV2.cvssV2.baseScore',
       'impact.baseMetricV2.exploitabilityScore',
       'impact.baseMetricV2.impactScore',
       'impact.baseMetricV2.cvssV2.accessVector_ADJACENT_NETWORK',
       'impact.baseMetricV2.cvssV2.accessVector_LOCAL',
       'impact.baseMetricV2.cvssV2.accessVector_NETWORK',
       'impact.baseMetricV2.cvssV2.accessComplexity_HIGH',
       'impact.baseMetricV2.cvssV2.accessComplexity_LOW',
       'impact.baseMetricV2.cvssV2.accessComplexity_MEDIUM',
       'impact.baseMetricV2.cvssV2.authentication_NONE',
       'impact.baseMetricV2.cvssV2.authentication_SINGLE',
       'impact.baseMetricV2.cvssV2.confidentialityImpact_COMPLETE',
       'impact.baseMetricV2.cvssV2.confidentialityImpact_NONE',
       'impact.baseMetricV2.cvssV2.confidentialityImpact_PARTIAL',
       'impact.baseMetricV2.cvssV2.integrityImpact_COMPLETE',
       'impact.baseMetricV2.cvssV2.integrityImpact_NONE',
       'impact.baseMetricV2.cvssV2.integrityImpact_PARTIAL',
       'impact.baseMetricV2.cvssV2.availabilityImpact_COMPLETE',
       'impact.baseMetricV2.cvssV2.availabilityImpact_NONE',
       'impact.baseMetricV2.cvssV2.availabilityImpact_PARTIAL',
       'impact.baseMetricV2.severity_HIGH', 'impact.baseMetricV2.severity_LOW',
       'impact.baseMetricV2.severity_MEDIUM',
       'impact.baseMetricV2.acInsufInfo_False',
       'impact.baseMetricV2.acInsufInfo_True',
       'impact.baseMetricV2.obtainAllPrivilege_False',
       'impact.baseMetricV2.obtainAllPrivilege_True',
       'impact.baseMetricV2.obtainUserPrivilege_False',
       'impact.baseMetricV2.obtainOtherPrivilege_False',
       'impact.baseMetricV2.userInteractionRequired_False',
       'impact.baseMetricV2.userInteractionRequired_True']
data = combined_data[features]

# Preprocess data as needed (handle missing values, convert categorical to numerical, etc.)

# 2. Feature Engineering

# Create additional features if required

# Remove unnecessary or redundant features

# 3. Splitting the Data

data_encoded = pd.get_dummies(data)

# Drop rows with NaN values
data_encoded.dropna(inplace=True)
X = data_encoded.drop('impact.baseMetricV3.impactScore', axis=1)  # Features (input)
y = data_encoded['impact.baseMetricV3.impactScore']  # Target variable

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


# 4. Model Selection and Training
model = LinearRegression()  # Choose your desired model here
model.fit(X_train, y_train)  # Train the model

# Print the learned coefficients
print("Coefficients:")
for feature, coef in enumerate(model.coef_):
    feature_name = X.columns[feature]
    print(f"{feature_name}: {coef}")

# Get feature importance (absolute value of coefficients)
importance = np.abs(model.coef_)

# Sort the importance and corresponding feature names
indices = np.argsort(importance)[::-1]
sorted_feature_names = [all_features[i] for i in indices]
sorted_importance = importance[indices]

# Print the feature importance
print("\nFeature Importance:")
for feature, importance in zip(sorted_feature_names, sorted_importance):
    print(f'{feature}: {importance:.4f}')


