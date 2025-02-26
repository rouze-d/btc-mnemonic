#!/usr/bin/python3

# Github : github.com/rouze-d
# -------------------------------------
# ============= INSTAL ================
# Windows: pip install bit bip32utils
# Linux: sudo python3 -m pip install --upgrade pip&&pip3 install bit bip32utils
# =====================================

import requests, re, json, base58, random, os, sys, binascii, bip32utils, codecs, argparse
from mnemonic import Mnemonic
from bit import Key
from bit.format import bytes_to_wif
from bit.crypto import ripemd160_sha256
from bit.base32 import encode
import bit


class Color():
    Red = '\33[31m'
    Green = '\33[32m'
    Yellow = '\33[33m'
    Cyan = '\33[36m'
    Grey = '\33[2m'
    Reset = '\033[0m'


red = Color.Red
green = Color.Green
yellow = Color.Yellow
cyan = Color.Cyan
reset = Color.Reset
grey = Color.Grey



def PrivateKeyFromMnemonic(Magic):
    for i in range(0, 1):
        Mw: str = Magic
        mne = Mnemonic("english")
        seed = mne.to_seed(Mw, passphrase="")
        Bip32_Root_Key_Object = bip32utils.BIP32Key.fromEntropy(seed)
        Bip32_Child_Key_Object = Bip32_Root_Key_Object.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(i)
        First_encode = base58.b58decode(Bip32_Child_Key_Object.WalletImportFormat())
        Private_Key_Byte = binascii.hexlify(First_encode)
        Private_Key_Hex = Private_Key_Byte[2:-10]

        Private_Hex = Private_Key_Hex.decode()
        bytePrivate = codecs.decode(Private_Hex, 'hex_codec')
        wifCompressed = bytes_to_wif(bytePrivate, compressed=True)
        wifUnCompressed = bytes_to_wif(bytePrivate, compressed=False)
        bit_com = Key(wifCompressed)
        bit_uncom = Key(wifUnCompressed)

        key = Key.from_hex(Private_Hex)

        compressedAddr = bit_com.address
        uncompressedAddr = bit_uncom.address


        sAddr = key.segwit_address

        public_key = bit.PrivateKey(wifCompressed).public_key
        public_key = ripemd160_sha256(public_key)
        bAddrW = encode('bc', 0, public_key)

# ----------------------------------------------------------------

        Bip32_Root_Key_Object1 = bip32utils.BIP32Key.fromEntropy(seed)
        Bip32_Child_Key_Object1 = Bip32_Root_Key_Object1.ChildKey(49 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(i)
        First_encode1 = base58.b58decode(Bip32_Child_Key_Object1.WalletImportFormat())
        Private_Key_Byte1 = binascii.hexlify(First_encode1)
        Private_Key_Hex1 = Private_Key_Byte1[2:-10]

        Private_Hex1 = Private_Key_Hex1.decode()
        bytePrivate1 = codecs.decode(Private_Hex1, 'hex_codec')
        wifCompressed1 = bytes_to_wif(bytePrivate1, compressed=True)
        wifUnCompressed1 = bytes_to_wif(bytePrivate1, compressed=False)
        bit_com1 = Key(wifCompressed1)
        bit_uncom1 = Key(wifUnCompressed1)

        key1 = Key.from_hex(Private_Hex1)

        compressedAddr1 = bit_com1.address
        uncompressedAddr1 = bit_uncom1.address

        sAddr1 = key.segwit_address

        public_key1 = bit.PrivateKey(wifCompressed1).public_key
        public_key1 = ripemd160_sha256(public_key1)
        bAddrW1 = encode('bc', 0, public_key1)


#----------------------------------------------------

        Bip32_Root_Key_Object2 = bip32utils.BIP32Key.fromEntropy(seed)
        Bip32_Child_Key_Object2 = Bip32_Root_Key_Object2.ChildKey(84 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(i)
        First_encode2 = base58.b58decode(Bip32_Child_Key_Object2.WalletImportFormat())
        Private_Key_Byte2 = binascii.hexlify(First_encode2)
        Private_Key_Hex2 = Private_Key_Byte2[2:-10]

        Private_Hex2 = Private_Key_Hex2.decode()
        bytePrivate2 = codecs.decode(Private_Hex2, 'hex_codec')
        wifCompressed2 = bytes_to_wif(bytePrivate2, compressed=True)
        wifUnCompressed2 = bytes_to_wif(bytePrivate2, compressed=False)
        bit_com2 = Key(wifCompressed2)
        bit_uncom2 = Key(wifUnCompressed2)

        key2 = Key.from_hex(Private_Hex2)

        compressedAddr2 = bit_com2.address
        uncompressedAddr2 = bit_uncom2.address

        sAddr2 = key.segwit_address

        public_key2 = bit.PrivateKey(wifCompressed2).public_key
        public_key2 = ripemd160_sha256(public_key2)
        bAddrW2 = encode('bc', 0, public_key2)

#---------------------------------------------------------

        Bip32_Root_Key_Object3 = bip32utils.BIP32Key.fromEntropy(seed)
        Bip32_Child_Key_Object3 = Bip32_Root_Key_Object3.ChildKey(86 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(i)
        First_encode3 = base58.b58decode(Bip32_Child_Key_Object3.WalletImportFormat())
        Private_Key_Byte3 = binascii.hexlify(First_encode3)
        Private_Key_Hex3 = Private_Key_Byte3[2:-10]

        Private_Hex3 = Private_Key_Hex3.decode()
        bytePrivate3 = codecs.decode(Private_Hex3, 'hex_codec')
        wifCompressed3 = bytes_to_wif(bytePrivate3, compressed=True)
        wifUnCompressed3 = bytes_to_wif(bytePrivate3, compressed=False)
        bit_com3 = Key(wifCompressed3)
        bit_uncom3 = Key(wifUnCompressed3)

        key3 = Key.from_hex(Private_Hex3)

        compressedAddr3 = bit_com3.address
        uncompressedAddr3 = bit_uncom3.address

        sAddr3 = key.segwit_address

        public_key3 = bit.PrivateKey(wifCompressed3).public_key
        public_key3 = ripemd160_sha256(public_key3)
        bAddrW3 = encode('bc', 0, public_key3)

#----------------------------------------------------------


        return compressedAddr, uncompressedAddr, sAddr, bAddrW, compressedAddr1, uncompressedAddr1, sAddr1, bAddrW1, compressedAddr2, uncompressedAddr2, sAddr2, bAddrW2, compressedAddr3, uncompressedAddr3, sAddr3, bAddrW3, Private_Hex, Private_Hex1, Private_Hex2, Private_Hex3
        #return compressedAddr, uncompressedAddr, sAddr, bAddrW, Private_Hex, wifCompressed, wifUnCompressed


def GetMnemonic():
    movies_list = ['abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse','access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act','action','actor','actress','actual','adapt','add','addict','address','adjust','admit','adult','advance','advice','aerobic','affair','afford','afraid','again','age','agent','agree','ahead','aim','air','airport','aisle','alarm','album','alcohol','alert','alien','all','alley','allow','almost','alone','alpha','already','also','alter','always','amateur','amazing','among','amount','amused','analyst','anchor','ancient','anger','angle','angry','animal','ankle','announce','annual','another','answer','antenna','antique','anxiety','any','apart','apology','appear','apple','approve','april','arch','arctic','area','arena','argue','arm','armed','armor','army','around','arrange','arrest','arrive','arrow','art','artefact','artist','artwork','ask','aspect','assault','asset','assist','assume','asthma','athlete','atom','attack','attend','attitude','attract','auction','audit','august','aunt','author','auto','autumn','average','avocado','avoid','awake','aware','away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge','bag','balance','balcony','ball','bamboo','banana','banner','bar','barely','bargain','barrel','base','basic','basket','battle','beach','bean','beauty','because','become','beef','before','begin','behave','behind','believe','below','belt','bench','benefit','best','betray','better','between','beyond','bicycle','bid','bike','bind','biology','bird','birth','bitter','black','blade','blame','blanket','blast','bleak','bless','blind','blood','blossom','blouse','blue','blur','blush','board','boat','body','boil','bomb','bone','bonus','book','boost','border','boring','borrow','boss','bottom','bounce','box','boy','bracket','brain','brand','brass','brave','bread','breeze','brick','bridge','brief','bright','bring','brisk','broccoli','broken','bronze','broom','brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb','bulk','bullet','bundle','bunker','burden','burger','burst','bus','business','busy','butter','buyer','buzz','cabbage','cabin','cable','cactus','cage','cake','call','calm','camera','camp','can','canal','cancel','candy','cannon','canoe','canvas','canyon','capable','capital','captain','car','carbon','card','cargo','carpet','carry','cart','case','cash','casino','castle','casual','cat','catalog','catch','category','cattle','caught','cause','caution','cave','ceiling','celery','cement','census','century','cereal','certain','chair','chalk','champion','change','chaos','chapter','charge','chase','chat','cheap','check','cheese','chef','cherry','chest','chicken','chief','child','chimney','choice','choose','chronic','chuckle','chunk','churn','cigar','cinnamon','circle','citizen','city','civil','claim','clap','clarify','claw','clay','clean','clerk','clever','click','client','cliff','climb','clinic','clip','clock','clog','close','cloth','cloud','clown','club','clump','cluster','clutch','coach','coast','coconut','code','coffee','coil','coin','collect','color','column','combine','come','comfort','comic','common','company','concert','conduct','confirm','congress','connect','consider','control','convince','cook','cool','copper','copy','coral','core','corn','correct','cost','cotton','couch','country','couple','course','cousin','cover','coyote','crack','cradle','craft','cram','crane','crash','crater','crawl','crazy','cream','credit','creek','crew','cricket','crime','crisp','critic','crop','cross','crouch','crowd','crucial','cruel','cruise','crumble','crunch','crush','cry','crystal','cube','culture','cup','cupboard','curious','current','curtain','curve','cushion','custom','cute','cycle','dad','damage','damp','dance','danger','daring','dash','daughter','dawn','day','deal','debate','debris','decade','december','decide','decline','decorate','decrease','deer','defense','define','defy','degree','delay','deliver','demand','demise','denial','dentist','deny','depart','depend','deposit','depth','deputy','derive','describe','desert','design','desk','despair','destroy','detail','detect','develop','device','devote','diagram','dial','diamond','diary','dice','diesel','diet','differ','digital','dignity','dilemma','dinner','dinosaur','direct','dirt','disagree','discover','disease','dish','dismiss','disorder','display','distance','divert','divide','divorce','dizzy','doctor','document','dog','doll','dolphin','domain','donate','donkey','donor','door','dose','double','dove','draft','dragon','drama','drastic','draw','dream','dress','drift','drill','drink','drip','drive','drop','drum','dry','duck','dumb','dune','during','dust','dutch','duty','dwarf','dynamic','eager','eagle','early','earn','earth','easily','east','easy','echo','ecology','economy','edge','edit','educate','effort','egg','eight','either','elbow','elder','electric','elegant','element','elephant','elevator','elite','else','embark','embody','embrace','emerge','emotion','employ','empower','empty','enable','enact','end','endless','endorse','enemy','energy','enforce','engage','engine','enhance','enjoy','enlist','enough','enrich','enroll','ensure','enter','entire','entry','envelope','episode','equal','equip','era','erase','erode','erosion','error','erupt','escape','essay','essence','estate','eternal','ethics','evidence','evil','evoke','evolve','exact','example','excess','exchange','excite','exclude','excuse','execute','exercise','exhaust','exhibit','exile','exist','exit','exotic','expand','expect','expire','explain','expose','express','extend','extra','eye','eyebrow','fabric','face','faculty','fade','faint','faith','fall','false','fame','family','famous','fan','fancy','fantasy','farm','fashion','fat','fatal','father','fatigue','fault','favorite','feature','february','federal','fee','feed','feel','female','fence','festival','fetch','fever','few','fiber','fiction','field','figure','file','film','filter','final','find','fine','finger','finish','fire','firm','first','fiscal','fish','fit','fitness','fix','flag','flame','flash','flat','flavor','flee','flight','flip','float','flock','floor','flower','fluid','flush','fly','foam','focus','fog','foil','fold','follow','food','foot','force','forest','forget','fork','fortune','forum','forward','fossil','foster','found','fox','fragile','frame','frequent','fresh','friend','fringe','frog','front','frost','frown','frozen','fruit','fuel','fun','funny','furnace','fury','future','gadget','gain','galaxy','gallery','game','gap','garage','garbage','garden','garlic','garment','gas','gasp','gate','gather','gauge','gaze','general','genius','genre','gentle','genuine','gesture','ghost','giant','gift','giggle','ginger','giraffe','girl','give','glad','glance','glare','glass','glide','glimpse','globe','gloom','glory','glove','glow','glue','goat','goddess','gold','good','goose','gorilla','gospel','gossip','govern','gown','grab','grace','grain','grant','grape','grass','gravity','great','green','grid','grief','grit','grocery','group','grow','grunt','guard','guess','guide','guilt','guitar','gun','gym','habit','hair','half','hammer','hamster','hand','happy','harbor','hard','harsh','harvest','hat','have','hawk','hazard','head','health','heart','heavy','hedgehog','height','hello','helmet','help','hen','hero','hidden','high','hill','hint','hip','hire','history','hobby','hockey','hold','hole','holiday','hollow','home','honey','hood','hope','horn','horror','horse','hospital','host','hotel','hour','hover','hub','huge','human','humble','humor','hundred','hungry','hunt','hurdle','hurry','hurt','husband','hybrid','ice','icon','idea','identify','idle','ignore','ill','illegal','illness','image','imitate','immense','immune','impact','impose','improve','impulse','inch','include','income','increase','index','indicate','indoor','industry','infant','inflict','inform','inhale','inherit','initial','inject','injury','inmate','inner','innocent','input','inquiry','insane','insect','inside','inspire','install','intact','interest','into','invest','invite','involve','iron','island','isolate','issue','item','ivory','jacket','jaguar','jar','jazz','jealous','jeans','jelly','jewel','job','join','joke','journey','joy','judge','juice','jump','jungle','junior','junk','just','kangaroo','keen','keep','ketchup','key','kick','kid','kidney','kind','kingdom','kiss','kit','kitchen','kite','kitten','kiwi','knee','knife','knock','know','lab','label','labor','ladder','lady','lake','lamp','language','laptop','large','later','latin','laugh','laundry','lava','law','lawn','lawsuit','layer','lazy','leader','leaf','learn','leave','lecture','left','leg','legal','legend','leisure','lemon','lend','length','lens','leopard','lesson','letter','level','liar','liberty','library','license','life','lift','light','like','limb','limit','link','lion','liquid','list','little','live','lizard','load','loan','lobster','local','lock','logic','lonely','long','loop','lottery','loud','lounge','love','loyal','lucky','luggage','lumber','lunar','lunch','luxury','lyrics','machine','mad','magic','magnet','maid','mail','main','major','make','mammal','man','manage','mandate','mango','mansion','manual','maple','marble','march','margin','marine','market','marriage','mask','mass','master','match','material','math','matrix','matter','maximum','maze','meadow','mean','measure','meat','mechanic','medal','media','melody','melt','member','memory','mention','menu','mercy','merge','merit','merry','mesh','message','metal','method','middle','midnight','milk','million','mimic','mind','minimum','minor','minute','miracle','mirror','misery','miss','mistake','mix','mixed','mixture','mobile','model','modify','mom','moment','monitor','monkey','monster','month','moon','moral','more','morning','mosquito','mother','motion','motor','mountain','mouse','move','movie','much','muffin','mule','multiply','muscle','museum','mushroom','music','must','mutual','myself','mystery','myth','naive','name','napkin','narrow','nasty','nation','nature','near','neck','need','negative','neglect','neither','nephew','nerve','nest','net','network','neutral','never','news','next','nice','night','noble','noise','nominee','noodle','normal','north','nose','notable','note','nothing','notice','novel','now','nuclear','number','nurse','nut','oak','obey','object','oblige','obscure','observe','obtain','obvious','occur','ocean','october','odor','off','offer','office','often','oil','okay','old','olive','olympic','omit','once','one','onion','online','only','open','opera','opinion','oppose','option','orange','orbit','orchard','order','ordinary','organ','orient','original','orphan','ostrich','other','outdoor','outer','output','outside','oval','oven','over','own','owner','oxygen','oyster','ozone','pact','paddle','page','pair','palace','palm','panda','panel','panic','panther','paper','parade','parent','park','parrot','party','pass','patch','path','patient','patrol','pattern','pause','pave','payment','peace','peanut','pear','peasant','pelican','pen','penalty','pencil','people','pepper','perfect','permit','person','pet','phone','photo','phrase','physical','piano','picnic','picture','piece','pig','pigeon','pill','pilot','pink','pioneer','pipe','pistol','pitch','pizza','place','planet','plastic','plate','play','please','pledge','pluck','plug','plunge','poem','poet','point','polar','pole','police','pond','pony','pool','popular','portion','position','possible','post','potato','pottery','poverty','powder','power','practice','praise','predict','prefer','prepare','present','pretty','prevent','price','pride','primary','print','priority','prison','private','prize','problem','process','produce','profit','program','project','promote','proof','property','prosper','protect','proud','provide','public','pudding','pull','pulp','pulse','pumpkin','punch','pupil','puppy','purchase','purity','purpose','purse','push','put','puzzle','pyramid','quality','quantum','quarter','question','quick','quit','quiz','quote','rabbit','raccoon','race','rack','radar','radio','rail','rain','raise','rally','ramp','ranch','random','range','rapid','rare','rate','rather','raven','raw','razor','ready','real','reason','rebel','rebuild','recall','receive','recipe','record','recycle','reduce','reflect','reform','refuse','region','regret','regular','reject','relax','release','relief','rely','remain','remember','remind','remove','render','renew','rent','reopen','repair','repeat','replace','report','require','rescue','resemble','resist','resource','response','result','retire','retreat','return','reunion','reveal','review','reward','rhythm','rib','ribbon','rice','rich','ride','ridge','rifle','right','rigid','ring','riot','ripple','risk','ritual','rival','river','road','roast','robot','robust','rocket','romance','roof','rookie','room','rose','rotate','rough','round','route','royal','rubber','rude','rug','rule','run','runway','rural','sad','saddle','sadness','safe','sail','salad','salmon','salon','salt','salute','same','sample','sand','satisfy','satoshi','sauce','sausage','save','say','scale','scan','scare','scatter','scene','scheme','school','science','scissors','scorpion','scout','scrap','screen','script','scrub','sea','search','season','seat','second','secret','section','security','seed','seek','segment','select','sell','seminar','senior','sense','sentence','series','service','session','settle','setup','seven','shadow','shaft','shallow','share','shed','shell','sheriff','shield','shift','shine','ship','shiver','shock','shoe','shoot','shop','short','shoulder','shove','shrimp','shrug','shuffle','shy','sibling','sick','side','siege','sight','sign','silent','silk','silly','silver','similar','simple','since','sing','siren','sister','situate','six','size','skate','sketch','ski','skill','skin','skirt','skull','slab','slam','sleep','slender','slice','slide','slight','slim','slogan','slot','slow','slush','small','smart','smile','smoke','smooth','snack','snake','snap','sniff','snow','soap','soccer','social','sock','soda','soft','solar','soldier','solid','solution','solve','someone','song','soon','sorry','sort','soul','sound','soup','source','south','space','spare','spatial','spawn','speak','special','speed','spell','spend','sphere','spice','spider','spike','spin','spirit','split','spoil','sponsor','spoon','sport','spot','spray','spread','spring','spy','square','squeeze','squirrel','stable','stadium','staff','stage','stairs','stamp','stand','start','state','stay','steak','steel','stem','step','stereo','stick','still','sting','stock','stomach','stone','stool','story','stove','strategy','street','strike','strong','struggle','student','stuff','stumble','style','subject','submit','subway','success','such','sudden','suffer','sugar','suggest','suit','summer','sun','sunny','sunset','super','supply','supreme','sure','surface','surge','surprise','surround','survey','suspect','sustain','swallow','swamp','swap','swarm','swear','sweet','swift','swim','swing','switch','sword','symbol','symptom','syrup','system','table','tackle','tag','tail','talent','talk','tank','tape','target','task','taste','tattoo','taxi','teach','team','tell','ten','tenant','tennis','tent','term','test','text','thank','that','theme','then','theory','there','they','thing','this','thought','three','thrive','throw','thumb','thunder','ticket','tide','tiger','tilt','timber','time','tiny','tip','tired','tissue','title','toast','tobacco','today','toddler','toe','together','toilet','token','tomato','tomorrow','tone','tongue','tonight','tool','tooth','top','topic','topple','torch','tornado','tortoise','toss','total','tourist','toward','tower','town','toy','track','trade','traffic','tragic','train','transfer','trap','trash','travel','tray','treat','tree','trend','trial','tribe','trick','trigger','trim','trip','trophy','trouble','truck','true','truly','trumpet','trust','truth','try','tube','tuition','tumble','tuna','tunnel','turkey','turn','turtle','twelve','twenty','twice','twin','twist','two','type','typical','ugly','umbrella','unable','unaware','uncle','uncover','under','undo','unfair','unfold','unhappy','uniform','unique','unit','universe','unknown','unlock','until','unusual','unveil','update','upgrade','uphold','upon','upper','upset','urban','urge','usage','use','used','useful','useless','usual','utility','vacant','vacuum','vague','valid','valley','valve','van','vanish','vapor','various','vast','vault','vehicle','velvet','vendor','venture','venue','verb','verify','version','very','vessel','veteran','viable','vibrant','vicious','victory','video','view','village','vintage','violin','virtual','virus','visa','visit','visual','vital','vivid','vocal','voice','void','volcano','volume','vote','voyage','wage','wagon','wait','walk','wall','walnut','want','warfare','warm','warrior','wash','wasp','waste','water','wave','way','wealth','weapon','wear','weasel','weather','web','wedding','weekend','weird','welcome','west','wet','whale','what','wheat','wheel','when','where','whip','whisper','wide','width','wife','wild','will','win','window','wine','wing','wink','winner','winter','wire','wisdom','wise','wish','witness','wolf','woman','wonder','wood','wool','word','work','world','worry','worth','wrap','wreck','wrestle','wrist','write','wrong','yard','year','yellow','you','young','youth','zebra','zero','zone','zoo']
    #count = 0
    #while (count == 0):

    length = 12
    password = " ".join(random.sample(movies_list,length))
    return(password)
    #count = 0
    #while (count == 0):
    #    return(random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list) + " " + random.choice(movies_list))
    #return f"{word1} {word2} {word3} {word4} {word5} {word6} {word7} {word8} {word9} {word10} {word11} {word12}"


parser = argparse.ArgumentParser()

parser.add_argument('-r', '--rich', type=str, dest='richFile', required=True, help="Rich File Name With .txt Format / Example: python -r richlist_file.txt")
parser.add_argument('-o', '--out', type=str, dest='outFound', required=True, help='Save Wallet Details in this file / Example: python -r richListFile.txt -o Found_Details.txt')
parser.add_argument('-t', '--thread', type=int, default=4, dest='thread', help='Thread Core Hunting , Default: 4')
args = parser.parse_args()

richFile = args.richFile
FoundFile = args.outFound
threadCount = args.thread

w = 0
z = 0
rl = [iu.strip() for iu in open(richFile).readlines()]
richList = set(rl)

while True:
    z += threadCount
    wod = GetMnemonic()
    compressAddress, UncompressAddress, sAddr, bAddrW, compressAddress1, UncompressAddress1, sAddr1, bAddrW1, compressAddress2, UncompressAddress2, sAddr2, bAddrW2, compressAddress3, UncompressAddress3, sAddr3, bAddrW3, PrivateKey, PrivateKey1, PrivateKey2, PrivateKey3 = PrivateKeyFromMnemonic(wod)
    #compressAddress, UncompressAddress, sAddr, bAddrW, PrivateKey, wifCompressed, wifUnCompressed = PrivateKeyFromMnemonic(wod)
    sys.stdout.write(f"\x1b]2;Total:{z} Found:{w}\x07")
    sys.stdout.flush()
    #if compressAddress in richList or UncompressAddress in richList or sAddr in richList or bAddrW in richList or bAddrT in richList:
    if compressAddress in richList or UncompressAddress in richList or sAddr in richList or bAddrW in richList or compressAddress1 in richList or UncompressAddress1 in richList or sAddr1 in richList or bAddrW1 in richList or compressAddress2 in richList or UncompressAddress2 in richList or sAddr2 in richList or bAddrW2 in richList or compressAddress3 in richList or UncompressAddress3 in richList or sAddr3 in richList or bAddrW3 in richList:
        w += 1
        open(FoundFile, 'a').write(f'COMPRESSED    : {compressAddress}\n'
                                   f'UNCOMPRESSED  : {UncompressAddress}\n'
                                   f'P2SH          : {sAddr}\n'
                                   f'BECH32/SEGWIT : {bAddrW}\n'
                                   f'PRIVATEKEY    HD wallet 44: {PrivateKey}\n'
                                   f'COMPRESSED    : {compressAddress1}\n'
                                   f'UNCOMPRESSED  : {UncompressAddress1}\n'
                                   f'P2SH          : {sAddr1}\n'
                                   f'BECH32/SEGWIT : {bAddrW1}\n'
                                   f'PRIVATEKEY    HD wallet 49: {PrivateKey1}\n'
                                   f'COMPRESSED    : {compressAddress2}\n'
                                   f'UNCOMPRESSED  : {UncompressAddress2}\n'
                                   f'P2SH          : {sAddr2}\n'
                                   f'BECH32/SEGWIT : {bAddrW2}\n'
                                   f'PRIVATEKEY    HD wallet 84: {PrivateKey2}\n'
                                   f'COMPRESSED    : {compressAddress3}\n'
                                   f'UNCOMPRESSED  : {UncompressAddress3}\n'
                                   f'P2SH          : {sAddr3}\n'
                                   f'BECH32/SEGWIT : {bAddrW3}\n'
                                   f'PRIVATEKEY    HD wallet 86: {PrivateKey3}\n'
                                   f'Mnemonic      : {wod}\n'
                                   f'----------------------------------------------------\n')
        print(f"Successfully Saved Match Address In Found.txt Can Checked Now.")

    else:
        lnm = f"{yellow}-{reset}"
        ln = f"{lnm} {green}-{reset}"
        print(f"{ln * 30}\n\n"
              f"[{cyan}{z}{reset}] {yellow}HD wallet (m/44'/0'/0'/0/0) | Compressed : {reset}{compressAddress}{yellow} | Uncompressed  : {reset}{UncompressAddress}\n"
              f"[{cyan}{z}{reset}] {yellow}HD wallet (m/44'/0'/0'/0/0) | P2SH       : {reset}{sAddr}{yellow} | Bech32/Segwit : {reset}{bAddrW}\n"
              f"[{cyan}{z}{reset}] {yellow}PrivateKey    : {reset}{green}{PrivateKey}{reset}\n"
              f"[{cyan}{z}{reset}] {yellow}HD wallet (m/49'/0'/0'/0/0) | Compressed : {reset}{compressAddress1}{yellow} | Uncompressed  : {reset}{UncompressAddress1}\n"
              f"[{cyan}{z}{reset}] {yellow}HD wallet (m/49'/0'/0'/0/0) | P2SH       : {reset}{sAddr1}{yellow} | Bech32/Segwit : {reset}{bAddrW1}\n"
              f"[{cyan}{z}{reset}] {yellow}PrivateKey    : {reset}{green}{PrivateKey1}{reset}\n"
              f"[{cyan}{z}{reset}] {yellow}HD wallet (m/84'/0'/0'/0/0) | Compressed : {reset}{compressAddress2}{yellow} | Uncompressed  : {reset}{UncompressAddress2}\n"
              f"[{cyan}{z}{reset}] {yellow}HD wallet (m/84'/0'/0'/0/0) | P2SH       : {reset}{sAddr2}{yellow} | Bech32/Segwit : {reset}{bAddrW2}\n"
              f"[{cyan}{z}{reset}] {yellow}PrivateKey    : {reset}{green}{PrivateKey2}{reset}\n"
              f"[{cyan}{z}{reset}] {yellow}HD wallet (m/89'/0'/0'/0/0) | Compressed : {reset}{compressAddress3}{yellow} | Uncompressed  : {reset}{UncompressAddress3}\n"
              f"[{cyan}{z}{reset}] {yellow}HD wallet (m/89'/0'/0'/0/0) | P2SH       : {reset}{sAddr3}{yellow} | Bech32/Segwit : {reset}{bAddrW3}\n"
              f"[{cyan}{z}{reset}] {yellow}PrivateKey    : {reset}{green}{PrivateKey3}{reset}\n"
              f"[{cyan}{z}{reset}] {yellow}Mnemonic      : {reset}{red}{wod}{reset}")
