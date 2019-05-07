

def password_check(password):
    val = True
    if len(password) < 8: 
        val = False
    if not any(char.isdigit() for char in password):  val = False
    if not any(char.isupper() for char in password): 
        val = False
    if not any(char.islower() for char in password):  val = False
    else:
        return val


    


    
    
