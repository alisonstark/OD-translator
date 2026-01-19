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

        elif(sub_technique == "002"):
            dic.update({"sub_technique_name": "AppleScript"})
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
        
        elif(sub_technique == "008"):
            dic.update({"sub_technique_name": "Network Device CLI"})
            return dic
        
        elif(sub_technique == "009"):
            dic.update({"sub_technique_name": "Cloud API"})
            return dic
        
        elif(sub_technique == "010"):
            dic.update({"sub_technique_name": "AutoHotKey & AutoIT"})
            return dic
        
        elif(sub_technique == "011"):
            dic.update({"sub_technique_name": "Lua"})
            return dic
        
        elif(sub_technique == "012"):
            dic.update({"sub_technique_name": "Hypervisor CLI"})
            return dic
        
        elif(sub_technique == "013"):
            dic.update({"sub_technique_name": "Container CLI/API"})
            return dic

        else:
            return dic  # No sub-technique matched, dict is empty
                    
    # Define other techniques (Far future)