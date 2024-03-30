import os
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from mitreattack.stix20 import MitreAttackData
import seaborn as sns

# ------------------ Helper Functions ------------------ #

# Load and cache the MITRE ATT&CK data
@st.cache_resource
def attack_data():
    attack_data = MitreAttackData("./data/enterprise-attack.json")
    return attack_data

attack_data = attack_data()

# Load and cache the list of threat actor groups
@st.cache_resource
def load_groups():
    groups = pd.read_json("./data/groups.json")
    return groups

groups = load_groups()


# ------------------ Streamlit UI ------------------ #

st.markdown("# <span style='color: #1DB954;'>APT D3T3CT 👽</span>", unsafe_allow_html=True)

st.markdown("""
            ### Select a Threat Actor Group

            Use the drop-down selector below to select a threat actor group from the MITRE ATT&CK framework and to view the corresponding metrics. 
            """)

selected_group_alias = st.selectbox("Select a threat actor group for the scenario",
                                     sorted(groups['group'].unique()),placeholder="Select Group", index=8, label_visibility="hidden")

phase_name_order = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 
                    'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 
                    'Collection', 'Command and Control', 'Exfiltration', 'Impact']

phase_name_category = pd.CategoricalDtype(categories=phase_name_order, ordered=True)



try:

    techniques_df = pd.DataFrame()
    selected_techniques_df = pd.DataFrame()

    if selected_group_alias != "Select Group":

        group = attack_data.get_groups_by_alias(selected_group_alias)
        group_url = groups[groups['group'] == selected_group_alias]['url'].values[0]

        if group:

            group_stix_id = group[0].id


            techniques = attack_data.get_techniques_used_by_group(group_stix_id)


            if not techniques:
                st.info(f"There are no Enterprise ATT&CK techniques associated with the threat group: {selected_group_alias}")
            else:

                techniques_df = pd.DataFrame(techniques)



            techniques_df['Technique Name'] = techniques_df['object'].apply(lambda x: x['name'])


            techniques_df['ATT&CK ID'] = techniques_df['object'].apply(lambda x: attack_data.get_attack_id(x['id']))


            techniques_df['Tactic'] = techniques_df['object'].apply(lambda x: x['kill_chain_phases'][0]['phase_name'])


            techniques_df = techniques_df.drop_duplicates(['Tactic', 'Technique Name', 'ATT&CK ID'])


            techniques_df['Tactic'] = techniques_df['Tactic'].str.replace('-', ' ').str.title()
        


            techniques_df['Tactic'] = techniques_df['Tactic'].replace('Command And Control', 'Command and Control')
            

            techniques_df['Detection'] = techniques_df['object'].apply(lambda x: x['x_mitre_detection'])
            
            techniques_df['Platform'] = techniques_df['object'].apply(lambda x: x['x_mitre_platforms'])
            
            techniques_df['Description'] = techniques_df['object'].apply(lambda x: x['description'])

            techniques_df['Tactic'] = techniques_df['Tactic'].astype(phase_name_category)
            

  
            techniques_df = techniques_df.sort_values('Tactic')
            


            techniques_df = techniques_df.sort_values('Tactic')

            techniques_df = techniques_df[['Technique Name', 'ATT&CK ID', 'Tactic', 'Description', 'Detection', 'Platform']]

            plt.style.use('dark_background')
            st.set_option('deprecation.showPyplotGlobalUse', False)
            st.markdown("APT Technique by Tactic")
            tactic_counts = techniques_df['Tactic'].value_counts()
            plt.figure(figsize=(20, 6))
            sns.set_palette("dark")
            sns.barplot(x=tactic_counts.index, y=tactic_counts.values) 
            plt.xlabel("Tactic", fontsize=20)
            plt.ylabel("Number of Techniques", fontsize=20)
            plt.xticks(rotation=45)
            st.pyplot()

        if not techniques_df.empty:

            with st.expander("                               APT ATT&CK Techniques                                                                                                      "):
                st.dataframe(data=techniques_df, height=None, use_container_width=True, width=None, hide_index=True)
                
        st.markdown( f"[View {selected_group_alias}'s page on attack.mitre.org]({group_url})")
        st.write ("Detection DataBank")
        kill_chain = []

        for index, row in techniques_df.iterrows():
            tactic = row['Tactic']
            technique_name = row['Technique Name']
            attack_id = row['ATT&CK ID']
            detection = row ['Detection']
            platform     = row ['Platform']
            kill_chain.append(f"{technique_name} ({attack_id}):  ***{detection}***")
        kill_chain_string = "\n".join(kill_chain)
        st.write(kill_chain,  hide_index=True)

except Exception as e:
    st.error("An error occurred: " + str(e))




