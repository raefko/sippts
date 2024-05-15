# https://fsymbols.com/generators/smallcaps/
# https://patorjk.com/software/taag/ - tmplr

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
        if self.script == 'sipscan':
            return '''
┏┓┳┏┓  ┏┓┏┓┏┓┳┓
┗┓┃┃┃  ┗┓┃ ┣┫┃┃
┗┛┻┣┛  ┗┛┗┛┛┗┛┗
            '''
        if self.script == 'sipexten':
            return '''
┏┓┳┏┓  ┏┓┏┓┏┓┏┳┓┏┓┳┓
┗┓┃┃┃  ┣  ┃┃  ┃ ┣ ┃┃
┗┛┻┣┛  ┗┛┗┛┗┛ ┻ ┗┛┛┗
            '''

        if self.script == 'siprcrack':
            return '''
┏┓┳┏┓  ┏┓┳┓┏┓┏┓┓┏┓
┗┓┃┃┃  ┃ ┣┫┣┫┃ ┃┫ 
┗┛┻┣┛  ┗┛┛┗┛┗┗┛┛┗┛
            '''

        if self.script == 'sipdigestleak':
            return '''
┏┓┳┏┓  ┳┓┳┏┓┏┓┏┓┏┳┓  ┓ ┏┓┏┓┓┏┓
┗┓┃┃┃  ┃┃┃┃┓┣ ┗┓ ┃   ┃ ┣ ┣┫┃┫ 
┗┛┻┣┛  ┻┛┻┗┛┗┛┗┛ ┻   ┗┛┗┛┛┗┛┗┛
            '''

        if self.script == 'sipinvite':
            return '''
┏┓┳┏┓  ┳┳┓┓┏┳┏┳┓┏┓
┗┓┃┃┃  ┃┃┃┃┃┃ ┃ ┣ 
┗┛┻┣┛  ┻┛┗┗┛┻ ┻ ┗┛
            '''

        if self.script == 'sipdigestcrack':
            return '''
┏┓┳┏┓  ┳┓┳┏┓┏┓┏┓┏┳┓  ┏┓┳┓┏┓┏┓┓┏┓
┗┓┃┃┃  ┃┃┃┃┓┣ ┗┓ ┃   ┃ ┣┫┣┫┃ ┃┫ 
┗┛┻┣┛  ┻┛┻┗┛┗┛┗┛ ┻   ┗┛┛┗┛┗┗┛┛┗┛

            '''

        if self.script == 'sipsend':
            return '''
┏┓┳┏┓  ┏┓┏┓┳┓┳┓
┗┓┃┃┃  ┗┓┣ ┃┃┃┃
┗┛┻┣┛  ┗┛┗┛┛┗┻┛
            '''

        if self.script == 'sipenumerate':
            return '''
┏┓┳┏┓  ┏┓┳┓┳┳┳┳┓┏┓┳┓┏┓┏┳┓┏┓
┗┓┃┃┃  ┣ ┃┃┃┃┃┃┃┣ ┣┫┣┫ ┃ ┣ 
┗┛┻┣┛  ┗┛┛┗┗┛┛ ┗┗┛┛┗┛┗ ┻ ┗┛
            '''

        if self.script == 'sippcapdump':
            return '''
┏┓┳┏┓  ┳┓┳┳┳┳┓┏┓
┗┓┃┃┃  ┃┃┃┃┃┃┃┃┃
┗┛┻┣┛  ┻┛┗┛┛ ┗┣┛
            '''

        if self.script == 'sipflood':
            return '''
┏┓┳┏┓  ┏┓┓ ┏┓┏┓┳┓
┗┓┃┃┃  ┣ ┃ ┃┃┃┃┃┃
┗┛┻┣┛  ┻ ┗┛┗┛┗┛┻┛
            '''

        if self.script == 'rtpbleed':
            return '''
┳┓┏┳┓┏┓  ┳┓┓ ┏┓┏┓┳┓
┣┫ ┃ ┃┃  ┣┫┃ ┣ ┣ ┃┃
┛┗ ┻ ┣┛  ┻┛┗┛┗┛┗┛┻┛
            '''

        if self.script == 'rtcpbleed':
            return '''
┳┓┏┳┓┏┓┏┓  ┳┓┓ ┏┓┏┓┳┓
┣┫ ┃ ┃ ┃┃  ┣┫┃ ┣ ┣ ┃┃
┛┗ ┻ ┗┛┣┛  ┻┛┗┛┗┛┗┛┻┛
            '''

        if self.script == 'rtpbleedflood':
            return '''
┳┓┏┓┏┓  ┳┓┓ ┏┓┏┓┳┓  ┏┓┓ ┏┓┏┓┳┓
┣┫┃ ┃┃  ┣┫┃ ┣ ┣ ┃┃  ┣ ┃ ┃┃┃┃┃┃
┛┗┗┛┣┛  ┻┛┗┛┗┛┗┛┻┛  ┻ ┗┛┗┛┗┛┻┛
            '''

        if self.script == 'rtpbleedinject':
            return '''
┳┓┏┓┏┓  ┳┓┓ ┏┓┏┓┳┓  ┳┳┓┏┳┏┓┏┓┏┳┓
┣┫┃ ┃┃  ┣┫┃ ┣ ┣ ┃┃  ┃┃┃ ┃┣ ┃  ┃ 
┛┗┗┛┣┛  ┻┛┗┛┗┛┗┛┻┛  ┻┛┗┗┛┗┛┗┛ ┻ 
            '''

        if self.script == 'siptshark':
            return '''
┏┓┳┏┓  ┏┳┓┏┓┓┏┏┓┳┓┓┏┓
┗┓┃┃┃   ┃ ┗┓┣┫┣┫┣┫┃┫ 
┗┛┻┣┛   ┻ ┗┛┛┗┛┗┛┗┛┗┛
            '''

        if self.script == 'arpspoof':
            return '''
┏┓┳┓┏┓  ┏┓┏┓┏┓┏┓┏┓
┣┫┣┫┃┃  ┗┓┃┃┃┃┃┃┣ 
┛┗┛┗┣┛  ┗┛┣┛┗┛┗┛┻ 
            '''

        if self.script == 'sipsniff':
            return '''
┏┓┳┏┓  ┏┓┳┓┳┏┓┏┓
┗┓┃┃┃  ┗┓┃┃┃┣ ┣ 
┗┛┻┣┛  ┗┛┛┗┻┻ ┻
            '''

        if self.script == 'sipping':
            return '''
┏┓┳┏┓  ┏┓┳┳┓┏┓
┗┓┃┃┃  ┃┃┃┃┃┃┓
┗┛┻┣┛  ┣┛┻┛┗┗┛
            '''

        if self.script == 'wssend':
            return '''
┓ ┏┏┓┏┓┏┓┳┓┳┓
┃┃┃┗┓┗┓┣ ┃┃┃┃
┗┻┛┗┛┗┛┗┛┛┗┻┛
            '''
