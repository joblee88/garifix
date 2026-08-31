// Data ya Mikoa, Wilaya na Kata za Tanzania - inatumika mfumo mzima
// (search_mechanics, request_service, mechanic_register)
const locationData = {
    "Arusha": {
        "Arusha Mjini": ["Baraa", "Daraja Mbili", "Elerai", "Engutoto", "Kaloleni", "Kati", "Kimandolu", "Lemara", "Levolosi", "Moshono", "Ngarenaro", "Olasiti", "Olturoto", "Sekei", "Sombetini", "Terrat", "Themi"],
        "Arumeru": ["Akheri", "Bangata", "Bwawani", "Ilkiding'a", "Kikwe", "King'ori", "Kiranyi", "Matesvesi", "Mbuguni", "Nkoanrua", "Nkoaranga", "Poli", "Singisi", "Usa River"],
        "Karatu": ["Baray", "Ganako", "Karatu", "Katesh", "Endabash", "Rhotia"],
        "Longido": ["Engarenaibor", "Engushai", "Longido", "Namanga", "Olmolog", "Tingatinga"],
        "Monduli": ["Engaruka", "Lepurko", "Makuyuni", "Monduli Mjini", "Mto wa Mbu", "Sepeko"],
        "Ngorongoro": ["Arash", "Digodigo", "Endulen", "Loliondo", "Ngaramtoni", "Olbalbal", "Sale"]
    },
    "Dar es Salaam": {
        "Ilala": ["Buguruni", "Gerezani", "Ilala", "Jangwani", "Kariakoo", "Kinyerezi", "Kipawa", "Kitunda", "Kisutu", "Mchafukoge", "Msasani", "Pugu", "Segerea", "Tabata", "Ukonga", "Upanga Mashariki", "Upanga Magharibi", "Vingunguti"],
        "Kigamboni": ["Kimbiji", "Kigamboni", "Kibada", "Kisarawe II", "Mjimwema", "Pembamnazi", "Somangila", "Tungi", "Vijibweni"],
        "Kinondoni": ["Bunju", "Hananasif", "Kawe", "Kijitonyama", "Kinondoni", "Kunduchi", "Magomeni", "Makumbusho", "Mbweni", "Mikocheni", "Msasani", "Mwananyamala", "Mbezi Beach", "Ndugumbi", "Tandale"],
        "Temeke": ["Azimio", "Buza", "Chamazi", "Chang'ombe", "Charambe", "Keko", "Kilakala", "Kurasini", "Mbagala", "Mbagala Kuu", "Mtoni", "Sandali", "Tandika", "Temeke", "Toangoma"],
        "Ubungo": ["Goba", "Kibamba", "Kimara", "Kwakhaberi", "Mabibo", "Manzese", "Mbezi", "Mburahati", "Msigani", "Saranga", "Sinza", "Ubungo"]
    },
    "Dodoma": {
        "Bahi": ["Bahi", "Ibundy", "Ipeluka", "Kipanga", "Lamaiti", "Mundemu", "Mpantile", "Zanka"],
        "Chamwino": ["Buigiri", "Chamwino", "Chilonwa", "Dabalo", "Fufu", "Ikowa", "Itiso", "Manchali", "Mvumi"],
        "Chemba": ["Chemba", "Farkwa", "Goima", "Kondoa", "Lalta", "Mondo", "Paranga"],
        "Dodoma Mjini": ["Bahi", "Chamwino", "Chang'ombe", "Hazina", "Ihumwa", "Ipagala", "Ipala", "Kizota", "Madale", "Majengo", "Makulu", "Mbweni", "Miyuji", "Mpwapwa", "Mtumba", "Njiapanda", "Nzuguni", "Tambukareli", "Zuzu"],
        "Kondoa": ["Bumbuta", "Kondoa Mjini", "Kolo", "Kinyasi", "Mondo", "Pahi", "Salanka"],
        "Kongwa": ["Hogoro", "Kibaigwa", "Kongwa", "Mlali", "Ngh'ambaku", "Sejeli", "Ugogoni"],
        "Mpwapwa": ["Godegode", "Gulwe", "Kibakwe", "Mpwapwa Mjini", "Pwinila", "Ving'hawe"]
    },
    "Geita": {
        "Bukombe": ["Buhalahala", "Busangi", "Ushirombo", "Uyovu"],
        "Chato": ["Bwanga", "Chato", "Kachwamba", "Muganza", "Nyarugusu"],
        "Geita Mjini": ["Bung'wangoko", "Bombambili", "Kalangalala", "Kanyala", "Mtakuja", "Nyang'hwale"],
        "Geita Vijijini": ["Bugulula", "Busanda", "Kamena", "Kharumwa", "Kotorukwa", "Nzera"],
        "Mbogwe": ["Ikombe", "Masumbwe", "Mbogwe", "Nyang'holongo"],
        "Nyang'hwale": ["Bukarai", "Kharumwa", "Nyamilama", "Nyang'hwale"]
    },
    "Iringa": {
        "Iringa Mjini": ["Gangilonga", "Igumbilo", "Kihesa", "Kwakilosa", "Mkwawa", "Mwangata", "Ruaha"],
        "Iringa Vijijini": ["Izazi", "Kalenga", "Kihorogota", "Migoli", "Mlali", "Nzihi"],
        "Kilolo": ["Ilula", "Kilolo", "Mahenge", "Mtitu", "Ruaha Mbuyuni", "Udzungwa"],
        "Mufindi": ["Boma", "Ifunda", "Igowole", "Mafinga", "Malangali", "Sadani"]
    },
    "Kagera": {
        "Biharamulo": ["Biharamulo", "Kabindi", "Kalenge", "Lusahunga", "Nyamigogo"],
        "Bukoba Mjini": ["Bakoba", "Bilele", "Hamugembe", "Kagondo", "Kashai", "Miembeni", "Nyamidati"],
        "Bukoba Vijijini": ["Kaibanja", "Kanyangereko", "Kyamulaile", "Mikoni", "Rubale"],
        "Karagwe": ["Bugene", "Kayanga", "Kibarizo", "Nyakakika", "Nyaishozi"],
        "Kyerwa": ["Bugomora", "Isingiro", "Kaisho", "Kyerwa", "Nkwenda"],
        "Misenyi": ["Bunazi", "Kasambya", "Kyaka", "Mutukula", "Nsunga"],
        "Muleba": ["Biirabo", "Kamachumu", "Magata", "Muleba", "Nshamba", "Rulenge"],
        "Ngara": ["Bugarama", "Kanazi", "Kabanga", "Ngara Mjini", "Rulenge"]
    },
    "Katavi": {
        "Mlele": ["Inyonga", "Ilela", "Kamsisi", "Mlele"],
        "Mpanda Mjini": ["Ilembo", "Kawanzugi", "Kashaulili", "Magamba", "Mpanda Hotel", "Shanwe"],
        "Mpanda Vijijini": ["Kabungu", "Karema", "Katuma", "Mishamo", "Sibwesa"],
        "Nsimbo": ["Katumba", "Litapunga", "Nsimbo", "Sitalike"]
    },
    "Kigoma": {
        "Buhigwe": ["Buhigwe", "Juhudi", "Munaze", "Muyama"],
        "Kakonko": ["Gwarama", "Kakonko", "Kasanda", "Nyamtukuza"],
        "Kasulu Mjini": ["Kigoma Road", "Murubona", "Nyumbigwa", "Kasingirima"],
        "Kasulu Vijijini": ["Heru Juu", "Kagera", "Makere", "Muzye", "Ruhita"],
        "Kibondo": ["Kibondo Mjini", "Mabamba", "Murungu", "Rugongowe"],
        "Kigoma Mjini": ["Bangwe", "Buzebazeba", "Gungu", "Kigoma", "Kipampa", "Mwanga", "Ujiji"],
        "Kigoma Vijijini": ["Kandaga", "Matyazo", "Mwamgongo", "Nsimbo"],
        "Uvinza": ["Basanza", "Ilagala", "Nguruka", "Uvinza"]
    },
    "Kilimanjaro": {
        "Hai": ["Bomang'ombe", "Machame Kaskazini", "Machame Mashariki", "Machame Magharibi", "Masama", "Weruweru"],
        "Moshi Mjini": ["Bomambuzi", "Kiboriloni", "Korongoni", "Majengo", "Mawenzi", "Miembeni", "Njoro", "Pasua", "Rau", "Shantyo"],
        "Moshi Vijijini": ["Kibosho", "Kimochi", "Kirimanjaro", "Marangu Kaskazini", "Marangu Kusini", "Uru", "Vunjo"],
        "Mwanga": ["Jipe", "Kifaru", "Lembeni", "Mwanga", "Shighatini", "Ugweno"],
        "Rombo": ["Himo", "Muu", "Mkuu", "Mashati", "Tarakea", "Useri"],
        "Same": ["Hedaru", "Kalema", "Mbaga", "Same Mjini", "Suji"],
        "Siha": ["Biriri", "Karansi", "Kashashi", "Sanya Juu", "Siha"]
    },
    "Lindi": {
        "Kilwa": ["Kipatimu", "Kilwa Masoko", "Kilwa Kivinje", "Lihimalao", "Mingumbi", "Songosongo"],
        "Lindi Mjini": ["Jamhuri", "Makonda", "Matopeni", "Mikindani", "Mwenge", "Nachingwea", "Rahaleo"],
        "Lindi Vijijini": ["Kiwalala", "Mchinga", "Mtama", "Nyangamara", "Soga"],
        "Liwale": ["Liwale Mjini", "Mirui", "Mpigamiti", "Nangando"],
        "Nachingwea": ["Kiluwa", "Marambo", "Mbondo", "Nachingwea Mjini", "Stesheni"],
        "Ruangwa": ["Lindi", "Mandawa", "Mnacho", "Nyangao", "Ruangwa Mjini"]
    },
    "Manyara": {
        "Babati Mjini": ["Babati", "Bonga", "Maisaka", "Nangara", "Singe"],
        "Babati Vijijini": ["Dareda", "Duru", "Gallapo", "Gorowa", "Magugu", "Qash"],
        "Hanang": ["Endasak", "Katesh", "Nangwa", "Ngasinyi", "Sirop"],
        "Kiteto": ["Bwawani", "Engusero", "Kibaya", "Matui", "Ndedo"],
        "Mbulu": ["Dongobesh", "Haydom", "Mbulu Mjini", "Tabora", "Yaeda Ampa"],
        "Simanjiro": ["Emboreet", "Mirerani", "Naberera", "Orkesumet", "Terrat"]
    },
    "Mara": {
        "Bunda": ["Bunda Stoo", "Bunda Mjini", "Guta", "Kibara", "Nansimo", "Sazira"],
        "Butiama": ["Butiama", "Kiabakari", "Kyamanyanja", "Mirwa", "Nyamimange"],
        "Musoma Mjini": ["Bwasi", "Iringo", "Kamunyonge", "Kitaji", "Mukendo", "Mwisenge", "Nyasho", "Nyabisare"],
        "Musoma Vijijini": ["Bwasi", "Etaro", "Mugango", "Nyang'oma", "Suguti"],
        "Rorya": ["Bukura", "Kinesi", "Kowak", "Nyamagaro", "Roche", "Shirati"],
        "Serengeti": ["Ikoma", "Issenye", "Mugumu", "Natta", "Rung'abure"],
        "Tarime": ["Bumera", "Gorong'a", "Nyamwaga", "Sirari", "Tarime Mjini", "Turwa"]
    },
    "Mbeya": {
        "Chunya": ["Chunya Mjini", "Chunguruma", "Ifumbo", "Itewe", "Matundasi", "Sangambi"],
        "Mbarali": ["Chimala", "Igurusi", "Igawa", "Lujewa", "Mbarali", "Rujewa", "Ubaruku"],
        "Mbeya Mjini": ["Forest", "Ghana", "Iyunga", "Iziwa", "Maanga", "Mbalizi Road", "Mwanjelwa", "Nsalaga", "Ruanda", "Simbawanga", "Soweto", "Uyole"],
        "Mbeya Vijijini": ["Ikuti", "Inyala", "Iziwa", "Mbalizi", "Utengule", "Tembela"],
        "Rungwe": ["Ilimba", "Kiwira", "Lufilyo", "Tukuyu Mjini", "Ushirika"]
    },
    "Morogoro": {
        "Gairo": ["Chagongwe", "Gairo", "Idibo", "Kinyolisi", "Madege"],
        "Kilombero": ["Ifakara", "Kidatu", "Kibatini", "Mang'ula", "Mlimba", "Mbingu", "Sanje"],
        "Kilosa": ["Chakwale", "Kimamba", "Kidodi", "Kilosa Mjini", "Mikumi", "Magole", "Ulaya"],
        "Morogoro Mjini": ["Boma", "Bwagala", "Kichangani", "Kingolwira", "Mazimbu", "Mbuyuni", "Mlimani", "Mwembesongo", "Sabasaba", "Sultani Area", "Tushurye"],
        "Morogoro Vijijini": ["Duthumi", "Kiroka", "Matombo", "Mvuha", "Ngerengere"],
        "Mvomero": ["Dakawa", "Hembeti", "Mhonda", "Mlali", "Mvomero", "Turiani"],
        "Ulanga": ["Isongo", "Lupiro", "Mahenge", "Mwaya", "Vigoi"],
        "Malinyi": ["Inebwe", "Itete", "Lutukila", "Malinyi", "Ngoheranga"]
    },
    "Mtwara": {
        "Masasi Mjini": ["Juhudi", "Mkomaindo", "Masasi Mjini", "Mwenge", "Nyasa", "Sululu"],
        "Masasi Vijijini": ["Lulindi", "Mchaururu", "Mbuyuni", "Nanjota", "Ndanda"],
        "Mtwara Mjini": ["Chikongola", "Chuno", "Jangwani", "Likoni", "Majengo", "Mitengo", "Naliendele", "Rahaleo", "Shangani", "Ufukoni"],
        "Mtwara Vijijini": ["Kitaya", "Mayanga", "Mahurunga", "Nanguruwe", "Ziwani"],
        "Nanyumbu": ["Lumesule", "Mangaka", "Nanyumbu", "Ndemba"],
        "Newala": ["Luchingu", "Makote", "Mcholi", "Newala Mjini", "Nambali"],
        "Tandahimba": ["Kitama", "Luagala", "Mahuta", "Mdimba", "Tandahimba Mjini"]
    },
    "Mwanza": {
        "Ilemela": ["Buzuruga", "Ilemela", "Kahama", "Kirumba", "Kitangiri", "Kiseke", "Mecco", "Nyamanoro", "Nyasaka", "Pasiansi", "Pasiansi Mashariki", "Sangabuye"],
        "Kwimba": ["Bhung'wangoko", "Igongwa", "Ngudu", "Ng'hundi", "Sumve"],
        "Magu": ["Kahangara", "Kisesa", "Lugeye", "Magu Mjini", "Nyanguge"],
        "Misungwi": ["Fella", "Idietiya", "Kisesa", "Misungwi", "Usagara"],
        "Nyamagana": ["Buhongwa", "Butimba", "Igogo", "Igoma", "Isamilo", "Kishiri", "Luchelele", "Mahina", "Mirongo", "Mkolani", "Mwatulole", "Nyamagana", "Nyegezi", "Pamba"],
        "Sengerema": ["Busisi", "Katunguru", "Mizizini", "Sengerema Mjini", "Tabaruka"],
        "Ukerewe": ["Bwiro", "Kagunguli", "Murutunguru", "Nansio", "Ushirika"]
    },
    "Njombe": {
        "Ludewa": ["Islowa", "Ludewa", "Manda", "Mlangali", "Mowembe"],
        "Makambako Mjini": ["Kipaganda", "Kitandililo", "Mjimwema", "Makambako", "Uwemba"],
        "Makete": ["Iwipe", "Iwawa", "Kitulo", "Lupila", "Matamba", "Uwimbi"],
        "Njombe Mjini": ["Ihalula", "Kimbila", "Lugenge", "Njombe Mjini", "Ramadhani", "Uwemba"],
        "Njombe Vijijini": ["Ikondo", "Kichiwa", "Matola", "Mtwango"],
        "Wanging'ombe": ["Igwachanya", "Kidugala", "Lupembe", "Wanging'ombe"]
    },
    "Pemba Kaskazini": {
        "Micheweni": ["Kiwuyu", "Micheweni", "Maziwangwa", "Wingwi"],
        "Wete": ["Gando", "Kojani", "Mtambwe", "Piki", "Utaani", "Wete Mjini"]
    },
    "Pemba Kusini": {
        "Chake Chake": ["Chake Chake Mjini", "Chonga", "Konde", "Ndagoni", "Wawi"],
        "Mkoani": ["Kangani", "Kengeja", "Makombeni", "Mkoani Mjini", "Mtambile"]
    },
    "Pwani": {
        "Bagamoyo": ["Dunda", "Fukayosi", "Kerege", "Kiwangwa", "Mapinga", "Yombo", "Zinga"],
        "Kibaha Mjini": ["Kibaha", "Kongowe", "Maili Moja", "Mlandizi", "Picha ya Ndege", "Tumbi", "Visiga"],
        "Kibaha Vijijini": ["Bokomnemela", "Gwata", "Kikula", "Magindu", "Ruvu"],
        "Kibiti": ["Bungu", "Kibiti", "Kiongoroni", "Mkuranga", "Salale"],
        "Kisarawe": ["Kazimzumbwi", "Kisarawe", "Kuruhi", "Maneromango", "Vikindu"],
        "Mafia": ["Baleni", "Kilindoni", "Kirongwe", "Kolekole"],
        "Mkuranga": ["Kisiju", "Kimanzichana", "Lukanga", "Mkuranga Mjini", "Vikindu", "Vianzi"],
        "Rufiji": ["Ikwiriri", "Kibiti", "Mohoro", "Utete Mjini"]
    },
    "Rukwa": {
        "Kalambo": ["Kasanga", "Matai", "Mwimbi", "Sopa"],
        "Sumbawanga Mjini": ["Katandala", "Kizwite", "Majengo", "Malay", "Milanzi", "Sumbawanga Mjini"],
        "Sumbawanga Vijijini": ["Kaengesa", "Laela", "Mfyoma", "Muze", "Sandulula"],
        "Nkasi": ["Kabwe", "Kirando", "Korongwe", "Namanyere", "Ninde"]
    },
    "Ruvuma": {
        "Mbinga": ["Kipapa", "Lituhi", "Mbinga Mjini", "Mbamba Bay", "Nyoni"],
        "Songea Mjini": ["Bombambili", "Majengo", "Matogoro", "Mshangano", "Ruvuma", "Subira", "Town Center"],
        "Songea Vijijini": ["Gumbiro", "Lilambo", "Maguu", "Peramiho", "Wino"],
        "Tunduru": ["Litunguru", "Masonya", "Mathias", "Mlingoti", "Tunduru Mjini"],
        "Namtumbo": ["Hanga", "Luchili", "Mgombasi", "Namtumbo Mjini"],
        "Nyasa": ["Kipili", "Kilosa", "Liuli", "Mbamba Bay", "Tinguni"]
    },
    "Shinyanga": {
        "Kahama Mjini": ["Busoka", "Isagehe", "Kahama Mjini", "Kagongwa", "Majengo", "Mhongolo", "Nyihogo", "Zongomera"],
        "Kahama Vijijini": ["Isaka", "Lunguya", "Mwingiro", "Ntobo", "Ukune"],
        "Kishapu": ["Bubinza", "Kishapu", "Mununwa", "Mwadui Mine", "Songwa"],
        "Shinyanga Mjini": ["Ibinzamata", "Kambarage", "Kitangiri", "Kizumbi", "Masekelo", "Ndembezi", "Shinyanga Mjini", "Uzini"],
        "Shinyanga Vijijini": ["Iselamagazi", "Luhumbo", "Lyabusalu", "Samuye", "Solwa"]
    },
    "Simiyu": {
        "Bariadi": ["Bariadi Mjini", "Bunamhala", "Giriadi", "Guduwi", "Nyakabindi", "Somanda"],
        "Busega": ["Kabita", "Kalemela", "Lamadi", "Mkula", "Ngasamo"],
        "Itilima": ["Bumera", "Chinamili", "Lagangabilili", "Migato", "Nkoma"],
        "Maswa": ["Badi", "Binza", "Isanga", "Maswa Mjini", "Nyabubinza", "Shanwa"],
        "Meatu": ["Kisesa", "Mwanhuzi", "Mwamapalala", "Mwubugi", "Tindabuligi"]
    },
    "Singida": {
        "Iramba": ["Kiomboi", "Kinampanda", "Mshelanga", "Nduguti", "Ulepwa"],
        "Ikungi": ["Dung'unyi", "Ihanja", "Ikungi", "Mgungira", "Sepuka"],
        "Manyoni": ["Chikuyu", "Hewe", "Kintinku", "Manyoni Mjini", "Solya"],
        "Mkalama": ["Gumanga", "Ibaga", "Kinyangiri", "Mkalama", "Nduguti"],
        "Singida Mjini": ["Ipembe", "Kindai", "Majengo", "Mandewa", "Mitunduruni", "Mungumaji", "Sewe", "Utemini"],
        "Singida Vijijini": ["Ilongero", "Kinyamwenda", "Mgori", "Mudida", "Ughandi"]
    },
    "Songwe": {
        "Ileje": ["Itumba", "Isongole", "Kasyabone", "Nyalwela", "Bupigu"],
        "Mbozi": ["Ichelo", "Isangati", "Iyula", "Mlowo", "Vwawa Mjini"],
        "Momba": ["Chitete", "Kamsamba", "Mkulwe", "Ndala", "Tunduma Mjini"],
        "Songwe": ["Kanga", "Mbangala", "Mwambani", "Saza"]
    },
    "Tabora": {
        "Igunga": ["Igunga Mjini", "Igurubi", "Kinungu", "Nkinga", "Simbo", "Sungwizi"],
        "Kaliua": ["Kaliua Mjini", "Kamukenge", "Kazaroho", "Milambo", "Urambo"],
        "Nzega": ["Bukene", "Lusu", "Ndala", "Nzega Mjini", "Puge", "Tinde"],
        "Sikonge": ["Chitemo", "Kitunda", "Miseno", "Sikonge Mjini", "Tutuo"],
        "Tabora Mjini": ["Cheyo", "Isevya", "Itonbula", "Kabila", "Kanyenye", "Kidatu", "Kitete", "Mpangala", "Nyamwezi", "Tambukareli", "Tabora"],
        "Urambo": ["Imalamakoye", "Muungano", "Songambele", "Urambo Mjini", "Usoke"],
        "Uyui": ["Igalula", "Ikongolo", "Lupeta", "Magiri", "Upuge"]
    },
    "Tanga": {
        "Handeni Mjini": ["Chanika", "Kwedizinga", "Mabanda", "Malezi", "Mnyuzi", "Vuruni"],
        "Handeni Vijijini": ["Kabuku", "Kivala", "Kwamatuku", "Kwang'andu", "Mziha"],
        "Kilindi": ["Kibirashi", "Kwediboma", "Songe Mjini", "Tunguli"],
        "Korogwe": ["Kwahumu", "Korogwe Mjini", "Magoma", "Majengo", "Manundu", "Mombo", "Mtimbwani"],
        "Lushoto": ["Bumbuli", "Funta", "Lushoto Mjini", "Malindi", "Mlalo", "Soni", "Uamboi"],
        "Mkinga": ["Duga", "Maramba", "Moa", "Mkinga Mjini", "Parungu Kasera"],
        "Muheza": ["Amani", "Bwembwera", "Kicheba", "Muheza Mjini", "Tingeni"],
        "Pangani": ["Bweni", "Kipumbwi", "Mwera", "Pangani Mjini", "Ubwini"],
        "Tanga Jiji": ["Chumbageni", "Central", "Dabalo", "Donge", "Kisemvule", "Kiomoni", "Mabayani", "Mazingara", "Mnyanjani", "Mwambani", "Ngamiani Kaskazini", "Ngamiani Kusini", "Niajema", "Pongwe", "Usagara"]
    },
    "Unguja Kaskazini": {
        "Kaskazini A": ["Chaani", "Gambrowa", "Kinyasini", "Mkokotoni", "Nungwi", "Tumbatu"],
        "Kaskazini B": ["Bumbwini", "Donge", "Kitope", "Mahonda", "Misufini"]
    },
    "Unguja Kusini": {
        "Kati": ["Bambi", "Dunga", "Jumbi", "Mitakawani", "Uroa"],
        "Kusini": ["Jambiani", "Kizimkazi", "Makunduchi", "Paje", "Unguja Ukuu"]
    },
    "Unguja Mjini Magharibi": {
        "Magharibi A": ["Bububu", "Chuini", "Kama", "Mtoni", "Welezo"],
        "Magharibi B": ["Fumba", "Fuoni", "Kiembe Samaki", "Mwanakerekwe", "Shakani"],
        "Mjini": ["Kikwajuni", "Malindi", "Mchangani", "Shangani", "Stone Town", "Vuga"]
    }
};
