import streamlit as st
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


API_KEY = "F4FMVVE5V85KG5SUIAN2P4TZJ2ZH43TUG6"

def get_transactions(address):
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&apikey={API_KEY}"
    response = requests.get(url)
    data = response.json()
    
    if data["status"] == "1":
        return data["result"]
    else:
        st.error("Invalid Address or API Issue")
        return []

# Function to detect ransomware using model 
def detect_ransomware(transactions):
    ransomware_wallets = {"0xcbeaec699431857fdb4d37addbbdc20e132d4903"}
    suspicious = []

    for tx in transactions:
        gas_used = int(tx["gasUsed"])
        value_eth = int(tx["value"]) / 10**18
        to_address = tx["to"]


        if gas_used > 100000 or to_address in ransomware_wallets:
                prediction = 1 
        else:
                prediction = 0
        if prediction == 1:
                suspicious.append(tx)

        else:
            if gas_used > 100000 or to_address in ransomware_wallets:
                suspicious.append(tx)

    return suspicious

# Streamlit UI
st.title("🔍 Cyber Threat Intelligence for Ransomware Detection in Ethereum Transactions")
eth_address = st.text_input("Enter Ethereum Address:", "")

if st.button("Analyze Transactions"):
    if eth_address:
        transactions = get_transactions(eth_address)
        ransomware_txs = detect_ransomware(transactions)

        df = pd.DataFrame(transactions)
        
        if not df.empty:
            required_columns = ["from", "to", "value", "gasUsed"]
            missing_columns = [col for col in required_columns if col not in df.columns]

            if missing_columns:
                st.error(f"Missing columns in the data: {missing_columns}")
            else:
                if ransomware_txs:
                    ransomware_df = pd.DataFrame(ransomware_txs)

                    st.subheader("📊 Transaction Analysis")
                    st.write(f"**Total Transactions:** {len(transactions)}")
                    st.write(f"**Suspicious Transactions:** {len(ransomware_txs)}")

                    labels = ["Safe", "Suspicious"]
                    sizes = [len(transactions) - len(ransomware_txs), len(ransomware_txs)]
                    plt.figure(figsize=(5, 5))
                    plt.pie(sizes, labels=labels, autopct="%1.1f%%", colors=["green", "red"])
                    st.pyplot(plt)

                    df["gasUsed"] = df["gasUsed"].astype(int)
                    top_gas_txs = df.nlargest(10, "gasUsed")
                    plt.figure(figsize=(8, 4))
                    sns.barplot(x="gasUsed", y="to", data=top_gas_txs, palette="Blues_r")
                    plt.xlabel("Gas Used")
                    plt.ylabel("Receiving Address")
                    plt.title("⛽ Top 10 Transactions by Gas Fee")
                    st.pyplot(plt)

                    st.subheader("🚨 Suspicious Transactions")
                    st.dataframe(ransomware_df[["from", "to", "value", "gasUsed"]])

                    if len(ransomware_txs) > 0:
                        st.error("⚠️ WARNING: Potential Ransomware Detected!")
                    else:
                        st.success("✅ Safe Transactions Detected")
                else:
                    st.warning("No suspicious transactions detected.")
        else:
            st.warning("No transactions found for the given address.")
    else:
        st.warning("Please enter a Ethereum address.")
