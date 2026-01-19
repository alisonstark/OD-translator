def check_technique_name(
        technique_id: str,
        sub_technique: str
) -> str:
    
    """
    What's not ideal (but OK for now):

            Hardcoded strings
            No return default
            No separation between technique metadata and logic
    """
    
    if(technique_id == "T1059"):
        if(sub_technique == "001"):
            return "Powershell"

        elif(sub_technique == "002"):
            return "AppleScript"
        
        elif(sub_technique == "003"):
            return "Windows Command Shell" 
        
        elif(sub_technique == "004"):
            return "Unix Shell"
        
        elif(sub_technique == "005"):
            return "Visual Basic"
        
        elif(sub_technique == "006"):
            return "Python"
        
        elif(sub_technique == "007"):
            return "JavaScript"
        
        elif(sub_technique == "008"):
            return "Network Device CLI"
        
        elif(sub_technique == "009"):
            return "Cloud API"
        
        elif(sub_technique == "010"):
            return "AutoHotKey & AutoIT"
        
        elif(sub_technique == "011"):
            return "Lua"
        
        elif(sub_technique == "012"):
            return "Hypervisor CLI"
        
        elif(sub_technique == "013"):
            return "Container CLI/API"

        else:
            return "Unknown Sub-technique"  # No sub-technique matched
                    
    # Define other techniques (Far future)