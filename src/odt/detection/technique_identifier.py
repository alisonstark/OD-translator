def check_technique_name(
        technique_id: str,
        sub_technique: str
) -> dict:
    
    """
    What's not ideal (but OK for now):

            Hardcoded strings
            No return default
            No separation between technique metadata and logic
    """
    
    dic = {}
    if(technique_id == "T1059"):
        dic.update({"technique_name": "Command and Scripting Interpreter"})
        if(sub_technique == "001"):
            dic.update({"sub_technique_name": "Powershell"})
            return dic
        
        elif(sub_technique == "003"):
            dic.update({"sub_technique_name": "Windows Command Shell"})
            return dic
        
        elif(sub_technique == "004"):
            dic.update({"sub_technique_name": "Unix Shell"})
            return dic
        
        elif(sub_technique == "005"):
            dic.update({"sub_technique_name": "Visual Basic"})
            return dic
        
        elif(sub_technique == "006"):
            dic.update({"sub_technique_name": "Python"})
            return dic
        
        elif(sub_technique == "007"):
            dic.update({"sub_technique_name": "JavaScript"})
            return dic
        
        elif(sub_technique == "011"):
            dic.update({"sub_technique_name": "Lua"})
            return dic

                    
    # Define other techniques (Far future)