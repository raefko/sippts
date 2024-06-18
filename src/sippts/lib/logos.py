# https://fsymbols.com/generators/smallcaps/
# https://patorjk.com/software/taag/ - tmplr - calvin s - small

import random
from .color import Color


class Logo:
    def __init__(self, script):
        self.script = script

        self.c = Color()
        
    def print(self):
        print('\n' + self.c.RED + u'''☎️  SIPPTS''' + self.c.WHITE +
              ''' BY ''' + self.c.GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + self.c.YELLOW)

        print(self.get_logo() + self.c.WHITE)

        print('' + self.c.BGREEN +
              '''💾 https://github.com/Pepelux/sippts''' + self.c.WHITE)
        print('' + self.c.BBLUE +
              '''🐦 https://twitter.com/pepeluxx\n''' + self.c.WHITE)


    def get_logo(self):
        if self.script == 'sippts':
            return '''
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠤⠶⠒⠛⠉⠉⠉⠉⠀⠀⢀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣬⣍⣙⣳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⠴⠒⠋⠉⠀⠀⠀⢀⣀⣠⡤⠴⠖⠚⠛⠉⠉⠉⠀⣠⡶⠖⠲⣄⠀⠀⠀⠀⠀⠀⠀⠈⠉⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡤⠖⠋⠁⠀⠀⠀⣀⣤⠴⠖⣛⣉⣁⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⡇⢹⡄⠀⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⡤⠞⠋⠀⠀⠀⢀⣠⠴⠚⠋⠁⠀⠀⡿⡏⠀⠈⣧⣤⠴⠖⠚⠛⠉⠉⠳⢄⡀⠀⣧⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⡞⠧⣄⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⢀⣴⠇⢹⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠉⣲⣿⣀⣠⣼⣦⣤⣀⣀⣀⡀⠀⢀⣀⣠⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⡿⠀⠀⠈⣿⠉⠀⠀⠀⠀⠀⠀⠙⢄⣰⠏⠀⠀⠘⡇⠀⠀⣇⢀⣀⡤⠤⠖⠒⠛⠉⠉⠉⣁⣀⠀⠀⠀⠉⠙⠛⢿⣿⡛⠛⠛⢻⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣸⣧⣄⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⡄⠀⠀⠀⣷⠴⠚⠋⠉⠀⠀⢀⣠⣴⡖⠛⠉⠿⢻⣿⣉⡉⠙⠓⢲⠦⢤⣈⠙⢶⣶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣰⡟⠿⡍⢷⢀⡇⠀⠀⠀⠀⠀⠀⠀⣠⣾⠏⣧⠀⢀⡞⠁⠀⠀⠀⠀⢠⡴⠋⠛⠻⣧⣤⡶⢿⡹⡟⠛⢯⣉⣿⢾⣧⣄⡈⠙⠲⢝⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣏⠙⢦⣹⣼⠀⠀⠀⠀⠀⠀⢀⣴⣾⠟⠁⢀⡏⢀⡞⠀⠀⠀⠀⠀⣰⣯⡟⡀⠀⣼⡏⢘⡢⢠⣷⣾⡿⠿⠿⣷⣤⣞⠀⠙⢦⡀⠀⠙⢿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣍⡓⣄⣿⣧⣤⣤⣤⣶⣶⠿⠟⠋⠀⠀⣠⣎⣠⠎⠘⢄⠀⠀⠀⢀⡏⠛⠙⠋⢸⠋⠧⠤⠗⣾⢻⠁⠀⠀⠀⠀⠈⠻⡳⡀⠀⠙⢦⠀⣠⡹⡟⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣷⣤⣙⢾⣿⣭⡉⠉⠉⠁⠀⠀⣀⣠⠴⠚⠉⠉⠀⠀⠀⠈⠳⡀⠀⠘⣧⣤⢀⠀⢸⡶⣏⠙⣦⠹⡜⢦⡀⠀⠀⠀⠀⢀⡇⣿⣶⣶⣾⣿⣥⡇⠹⡌⠻⣄⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠤⢬⣿⣇⠈⢹⡟⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢆⠀⢻⡹⡎⠃⠀⠳⡄⣽⠛⠦⠉⠲⣍⣓⣒⢒⣒⣉⡴⠋⣟⠙⢲⣿⠘⠃⠀⣷⠀⠙⢧⡀⠀⠀⠀⠀⠀⠀
⣿⠶⠒⠺⣿⡀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢣⡀⠳⡄⢀⡀⠀⠙⠮⣗⠚⢠⡖⠲⣌⣉⡭⣍⡡⣞⠓⣾⠉⣽⠃⢠⡄⣼⣿⠀⠀⠈⠳⡄⠀⠀⠀⠀⠀
⠸⡟⠉⣉⣻⣧⣼⠿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣄⠙⢮⡿⢿⡃⠀⠈⠑⠶⢽⣒⣃⣘⣲⣤⣗⣈⣹⠵⠛⠁⠀⠀⡴⣻⠃⠀⠀⠀⠀⠹⣆⠀⠀⠀⠀
⠀⠹⣯⣁⣠⠼⠿⣿⡲⠿⠷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⠀⠙⠳⣄⡀⠀⣄⣶⣄⠀⠉⠉⠉⣉⡉⠉⠀⠀⠘⣶⣴⣦⠞⠁⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀
⠀⠀⠘⣧⡤⠖⢋⣩⠿⣶⣤⣈⣙⣷⣤⣀⣠⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⡀⠀⠀⠉⠓⠶⢽⣼⣆⡀⠀⠀⢿⣿⣶⣀⣀⡬⠷⠚⠁⣀⣀⣀⠀⢰⣿⠿⡇⠀⠘⣧⠀⠀
⠀⠀⠀⠀⠙⠾⣏⣤⠞⢁⡞⠉⣿⠋⣹⠉⢹⠀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠀⣤⣤⣄⠀⣿⠙⢻⠆⠀⠓⢒⣁⡤⠴⠺⡆⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠒⠻⠤⣴⣇⣀⣿⣀⣾⡤⠿⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⣀⣀⡀⠀⢸⠿⢷⡄⠀⣿⣀⡿⠀⢈⣉⡭⠴⠒⠋⠉⠀⠀⠀⠀⢻⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠀⠰⣟⠛⡇⠀⠘⠧⠞⢁⣀⡤⠴⠒⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣼⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣦⣀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠉⢋⣁⡤⠴⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣴⠶⠚⠛⠉⢉⣽⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣤⡀⠀⠀⠀⠀⠘⡆⠴⠒⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠴⠖⠛⠉⠉⠉⠉⠙⠛⠋⠉⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢛⠷⠦⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⢠⠴⡖⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
     '''
        
        rnd = random.randint(1, 3)

        if self.script == 'sipscan':
            if rnd == 1:
                return '''
    ┏┓┳┏┓┏┓┏┳┓┏┓        
    ┗┓┃┃┃┃┃ ┃ ┗┓  ┏┏┏┓┏┓
    ┗┛┻┣┛┣┛ ┻ ┗┛  ┛┗┗┻┛┗
                '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌─┐┌─┐┌┐┌
╚═╗║╠═╝╠═╝ ║ ╚═╗  └─┐│  ├─┤│││
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘└─┘┴ ┴┘└┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                    
 / __|_ _| _ \\ _ \\_   _/ __|  ___ __ __ _ _ _  
 \\__ \\| ||  _/  _/ | | \\__ \\ (_-</ _/ _` | ' \\ 
 |___/___|_| |_|   |_| |___/ /__/\\__\\__,_|_||_|
            '''
        if self.script == 'sipexten':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓           
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓┓┏╋┏┓┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┗ ┛┗┗┗ ┛┗
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐─┐ ┬┌┬┐┌─┐┌┐┌
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┤ ┌┴┬┘ │ ├┤ │││
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘┴ └─ ┴ └─┘┘└┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___           _            
 / __|_ _| _ \\ _ \\_   _/ __|  _____ _| |_ ___ _ _  
 \\__ \\| ||  _/  _/ | | \\__ \\ / -_) \\ /  _/ -_) ' \\ 
 |___/___|_| |_|   |_| |___/ \\___/_\\_\\__\\___|_||_|
                '''

        if self.script == 'siprcrack':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓          ┓ 
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓┏┏┓┏┓┏┃┏
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┛ ┗┻┗┛┗
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌─┐┬─┐┌─┐┌─┐┬┌─
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘│  ├┬┘├─┤│  ├┴┐
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─└─┘┴└─┴ ┴└─┘┴ ┴
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                      _   
 / __|_ _| _ \\ _ \\_   _/ __|  _ _ __ _ _ __ _ __| |__
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_/ _| '_/ _` / _| / /
 |___/___|_| |_|   |_| |___/ |_| \\__|_| \\__,_\\__|_\\_\\
                '''

        if self.script == 'sipdigestleak':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  ┓    ┓ 
┗┓┃┃┃┃┃ ┃ ┗┓  ┃┏┓┏┓┃┏
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┗ ┗┻┛┗
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬  ┌─┐┌─┐┬┌─
╚═╗║╠═╝╠═╝ ║ ╚═╗  │  ├┤ ├─┤├┴┐
╚═╝╩╩  ╩   ╩ ╚═╝  ┴─┘└─┘┴ ┴┴ ┴
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___   _          _   
 / __|_ _| _ \\ _ \\_   _/ __| | |___ __ _| |__
 \\__ \\| ||  _/  _/ | | \\__ \\ | / -_) _` | / /
 |___/___|_| |_|   |_| |___/ |_\\___\\__,_|_\\_\\
                '''

        if self.script == 'sipinvite':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  •    •   
┗┓┃┃┃┃┃ ┃ ┗┓  ┓┏┓┓┏┓╋┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┛┗┗┛┗┗┗ 
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬┌┐┌┬  ┬┬┌┬┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ││││└┐┌┘│ │ ├┤ 
╚═╝╩╩  ╩   ╩ ╚═╝  ┴┘└┘ └┘ ┴ ┴ └─┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___   _         _ _       
 / __|_ _| _ \\ _ \\_   _/ __| (_)_ ___ _(_) |_ ___ 
 \\__ \\| ||  _/  _/ | | \\__ \\ | | ' \\ V / |  _/ -_)
 |___/___|_| |_|   |_| |___/ |_|_||_\\_/|_|\\__\\___|
                '''

        if self.script == 'sipdigestcrack':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓   ┓      ┓ 
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┫┏┏┓┏┓┏┃┏
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┻┗┛ ┗┻┗┛┗
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌┬┐┌─┐┬─┐┌─┐┌─┐┬┌─
╚═╗║╠═╝╠═╝ ║ ╚═╗   │││  ├┬┘├─┤│  ├┴┐
╚═╝╩╩  ╩   ╩ ╚═╝  ─┴┘└─┘┴└─┴ ┴└─┘┴ ┴
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___      _                _   
 / __|_ _| _ \\ _ \\_   _/ __|  __| |__ _ _ __ _ __| |__
 \\__ \\| ||  _/  _/ | | \\__ \\ / _` / _| '_/ _` / _| / /
 |___/___|_| |_|   |_| |___/ \\__,_\\__|_| \\__,_\\__|_\\_\\
                '''

        if self.script == 'sipsend':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓        ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛┗ ┛┗┗┻
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌─┐┌┐┌┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  └─┐├┤ │││ ││
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘└─┘┘└┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                   _ 
 / __|_ _| _ \\ _ \\_   _/ __|  ___ ___ _ _  __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ (_-</ -_) ' \\/ _` |
 |___/___|_| |_|   |_| |___/ /__/\\___|_||_\\__,_|
                '''

        if self.script == 'sipenumerate':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓                    
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓┏┓┓┏┏┳┓┏┓┏┓┏┓╋┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┗ ┛┗┗┻┛┗┗┗ ┛ ┗┻┗┗ 
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌┐┌┬ ┬┌┬┐┌─┐┬─┐┌─┐┌┬┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┤ ││││ ││││├┤ ├┬┘├─┤ │ ├┤ 
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘┘└┘└─┘┴ ┴└─┘┴└─┴ ┴ ┴ └─┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                                   _       
 / __|_ _| _ \\ _ \\_   _/ __|  ___ _ _ _  _ _ __  ___ _ _ __ _| |_ ___ 
 \\__ \\| ||  _/  _/ | | \\__ \\ / -_) ' \\ || | '  \\/ -_) '_/ _` |  _/ -_)
 |___/___|_| |_|   |_| |___/ \\___|_||_\\_,_|_|_|_\\___|_| \\__,_|\\__\\___|
                '''

        if self.script == 'sipdump':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓   ┓       
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┫┓┏┏┳┓┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┻┗┻┛┗┗┣┛
                     ┛
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌┬┐┬ ┬┌┬┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗   │││ ││││├─┘
╚═╝╩╩  ╩   ╩ ╚═╝  ─┴┘└─┘┴ ┴┴  
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___      _                 
 / __|_ _| _ \\ _ \\_   _/ __|  __| |_  _ _ __  _ __ 
 \\__ \\| ||  _/  _/ | | \\__ \\ / _` | || | '  \\| '_ \\
 |___/___|_| |_|   |_| |___/ \\__,_|\\_,_|_|_|_| .__/
                                             |_|  
                '''

        if self.script == 'sipflood':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  ┏┓     ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ╋┃┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛┗┗┛┗┛┗┻
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┬  ┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┤ │  │ ││ │ ││
╚═╝╩╩  ╩   ╩ ╚═╝  └  ┴─┘└─┘└─┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___    __ _              _ 
 / __|_ _| _ \\ _ \\_   _/ __|  / _| |___  ___  __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ |  _| / _ \\/ _ \\/ _` |
 |___/___|_| |_|   |_| |___/ |_| |_\\___/\\___/\\__,_|
                '''

        if self.script == 'rtpbleed':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓       ┓ ┓     ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓╋┏┓┣┓┃┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┣┛┗┛┗┗ ┗ ┗┻
                 ┛          
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌┬┐┌─┐┌┐ ┬  ┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘ │ ├─┘├┴┐│  ├┤ ├┤  ││
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─ ┴ ┴  └─┘┴─┘└─┘└─┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___       _        _    _            _ 
 / __|_ _| _ \\ _ \\_   _/ __|  _ _| |_ _ __| |__| |___ ___ __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_|  _| '_ \\ '_ \\ / -_) -_) _` |
 |___/___|_| |_|   |_| |___/ |_|  \\__| .__/_.__/_\\___\\___\\__,_|
                                     |_|                       
                '''

        if self.script == 'rtcpbleed':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓        ┓ ┓     ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓╋┏┏┓┣┓┃┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┗┣┛┗┛┗┗ ┗ ┗┻
                  ┛          
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌┬┐┌─┐┌─┐┌┐ ┬  ┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘ │ │  ├─┘├┴┐│  ├┤ ├┤  ││
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─ ┴ └─┘┴  └─┘┴─┘└─┘└─┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___       _           _    _            _ 
 / __|_ _| _ \\ _ \\_   _/ __|  _ _| |_ __ _ __| |__| |___ ___ __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_|  _/ _| '_ \\ '_ \\ / -_) -_) _` |
 |___/___|_| |_|   |_| |___/ |_|  \\__\\__| .__/_.__/_\\___\\___\\__,_|
                                        |_|                      
                '''

        if self.script == 'rtpbleedflood':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓       ┓ ┓     ┓┏┓     ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓╋┏┓┣┓┃┏┓┏┓┏┫╋┃┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┣┛┗┛┗┗ ┗ ┗┻┛┗┗┛┗┛┗┻
                 ┛                  
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌┬┐┌─┐┌┐ ┬  ┌─┐┌─┐┌┬┐┌─┐┬  ┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘ │ ├─┘├┴┐│  ├┤ ├┤  ││├┤ │  │ ││ │ ││
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─ ┴ ┴  └─┘┴─┘└─┘└─┘─┴┘└  ┴─┘└─┘└─┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___       _        _    _            _  __ _              _ 
 / __|_ _| _ \\ _ \\_   _/ __|  _ _| |_ _ __| |__| |___ ___ __| |/ _| |___  ___  __| |
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_|  _| '_ \\ '_ \\ / -_) -_) _` |  _| / _ \\/ _ \\/ _` |
 |___/___|_| |_|   |_| |___/ |_|  \\__| .__/_.__/_\\___\\___\\__,_|_| |_\\___/\\___/\\__,_|
                                     |_|                                           
                '''

        if self.script == 'rtpbleedinject':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓       ┓ ┓     ┓•  •    
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓╋┏┓┣┓┃┏┓┏┓┏┫┓┏┓┓┏┓┏╋
┗┛┻┣┛┣┛ ┻ ┗┛  ┛ ┗┣┛┗┛┗┗ ┗ ┗┻┗┛┗┃┗ ┗┗
                 ┛             ┛    
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┬─┐┌┬┐┌─┐┌┐ ┬  ┌─┐┌─┐┌┬┐┬┌┐┌ ┬┌─┐┌─┐┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├┬┘ │ ├─┘├┴┐│  ├┤ ├┤  ││││││ │├┤ │   │ 
╚═╝╩╩  ╩   ╩ ╚═╝  ┴└─ ┴ ┴  └─┘┴─┘└─┘└─┘─┴┘┴┘└┘└┘└─┘└─┘ ┴
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___       _        _    _            _ _       _        _   
 / __|_ _| _ \\ _ \\_   _/ __|  _ _| |_ _ __| |__| |___ ___ __| (_)_ _  (_)___ __| |_ 
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_|  _| '_ \\ '_ \\ / -_) -_) _` | | ' \\ | / -_) _|  _|
 |___/___|_| |_|   |_| |___/ |_|  \\__| .__/_.__/_\\___\\___\\__,_|_|_||_|/ \\___\\__|\\__|
                                     |_|                            |__/            
                '''

        if self.script == 'arpspoof':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓         ┏
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┏┓┏┓┏┓╋
┗┛┻┣┛┣┛ ┻ ┗┛  ┛┣┛┗┛┗┛┛
               ┛   
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌─┐┌─┐┌─┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  └─┐├─┘│ ││ │├┤ 
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘┴  └─┘└─┘└  
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___                      __ 
 / __|_ _| _ \\ _ \\_   _/ __|  ____ __  ___  ___ / _|
 \\__ \\| ||  _/  _/ | | \\__ \\ (_-< '_ \\/ _ \\/ _ \\  _|
 |___/___|_| |_|   |_| |___/ /__/ .__/\\___/\\___/_|  
                                |_|                 
                '''

        if self.script == 'sipsniff':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓     •┏┏
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┏┓┓╋╋
┗┛┻┣┛┣┛ ┻ ┗┛  ┛┛┗┗┛┛                   
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┌┐┌┬┌─┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  └─┐││││├┤ ├┤ 
╚═╝╩╩  ╩   ╩ ╚═╝  └─┘┘└┘┴└  └  
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___           _  __  __ 
 / __|_ _| _ \\ _ \\_   _/ __|  ____ _ (_)/ _|/ _|
 \\__ \\| ||  _/  _/ | | \\__ \\ (_-< ' \\| |  _|  _|
 |___/___|_| |_|   |_| |___/ /__/_||_|_|_| |_|                                                  
                '''

        if self.script == 'sipping':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓    •    
┗┓┃┃┃┃┃ ┃ ┗┓  ┏┓┓┏┓┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┣┛┗┛┗┗┫
              ┛     ┛
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ┌─┐┬┌┐┌┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ├─┘│││││ ┬
╚═╝╩╩  ╩   ╩ ╚═╝  ┴  ┴┘└┘└─┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___        _           
 / __|_ _| _ \\ _ \\_   _/ __|  _ __(_)_ _  __ _ 
 \\__ \\| ||  _/  _/ | | \\__ \\ | '_ \\ | ' \\/ _` |
 |___/___|_| |_|   |_| |___/ | .__/_|_||_\\__, |
                             |_|         |___/ 
                '''

        if self.script == 'wssend':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  ┓ ┏┏┓        ┓
┗┓┃┃┃┃┃ ┃ ┗┓  ┃┃┃┗┓  ┏┏┓┏┓┏┫
┗┛┻┣┛┣┛ ┻ ┗┛  ┗┻┛┗┛  ┛┗ ┛┗┗┻
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ╦ ╦╔═╗  ┌─┐┌─┐┌┐┌┌┬┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ║║║╚═╗  └─┐├┤ │││ ││
╚═╝╩╩  ╩   ╩ ╚═╝  ╚╩╝╚═╝  └─┘└─┘┘└┘─┴┘
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___  __      _____                   _ 
 / __|_ _| _ \\ _ \\_   _/ __| \\ \\    / / __|  ___ ___ _ _  __| |
 \\__ \\| ||  _/  _/ | | \\__ \\  \\ \\/\\/ /\\__ \\ (_-</ -_) ' \\/ _` |
 |___/___|_| |_|   |_| |___/   \\_/\\_/ |___/ /__/\\___|_||_\\__,_|                                                               
                '''

        if self.script == 'sippcapdump':
            if rnd == 1:
                return '''
┏┓┳┏┓┏┓┏┳┓┏┓  ┏┓┏┓┏┓┏┓   ┓       
┗┓┃┃┃┃┃ ┃ ┗┓  ┃┃┃ ┣┫┃┃  ┏┫┓┏┏┳┓┏┓
┗┛┻┣┛┣┛ ┻ ┗┛  ┣┛┗┛┛┗┣┛  ┗┻┗┻┛┗┗┣┛
                               ┛ 
            '''
            elif rnd == 2:
                return '''
╔═╗╦╔═╗╔═╗╔╦╗╔═╗  ╔═╗╔═╗╔═╗╔═╗  ┌┬┐┬ ┬┌┬┐┌─┐
╚═╗║╠═╝╠═╝ ║ ╚═╗  ╠═╝║  ╠═╣╠═╝   │││ ││││├─┘
╚═╝╩╩  ╩   ╩ ╚═╝  ╩  ╚═╝╩ ╩╩    ─┴┘└─┘┴ ┴┴  
                '''
            elif rnd == 3:
                return '''
  ___ ___ ___ ___ _____ ___   ___  ___   _   ___      _                 
 / __|_ _| _ \\ _ \\_   _/ __| | _ \\/ __| /_\\ | _ \\  __| |_  _ _ __  _ __ 
 \\__ \\| ||  _/  _/ | | \\__ \\ |  _/ (__ / _ \\|  _/ / _` | || | '  \\| '_ \\
 |___/___|_| |_|   |_| |___/ |_|  \\___/_/ \\_\\_|   \\__,_|\\_,_|_|_|_| .__/
                                                                  |_|   
                '''
