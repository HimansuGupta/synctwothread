package main

import (
	"log"
)

func main() {
	log.Println("Start")
	done := make(chan bool)
	sync := make(chan bool)
	number := 10

	go evenNumber(number, sync, done)
	sync <- true
	go oddNumber(number, sync, done)

	<-done
	close(sync)
}

func evenNumber(number int, sync, done chan bool) {
	for i := 0; i <= number; i++ {
		<-sync
		if i%2 == 0 {
			log.Println("Even :: ", i)
		}
		sync <- true
	}
	done <- true
}

func oddNumber(number int, sync, done chan bool) {
	for i := 0; i <= number; i++ {
		<-sync
		if i%2 != 0 {
			log.Println("Odd :: ", i)
		}
		sync <- true
	}
	done <- true
}

// func selfDivide(number int) {
// 	for i := 4; i <= number; i++ {
// 		j := 2
// 		flag := true
// 		for ; j <= i/2+1; j++ {
// 			if i%j == 0 {
// 				//log.Println("Self not diveded :: ", i)
// 				flag = false
// 				break
// 			}
// 		}

// 		if flag {
// 			log.Println("Self diveded :: ", i)
// 		}
// 		//sync <- true
// 	}
// 	//done <- true
// }

// now := time.Now().UTC()
// 	fmt.Println(now)
// 	fmt.Println(now.UTC().Location())
// 	fmt.Println(now.UTC().Hour())

// 	// Calculate the time remaining until 11:59:59 PM today
// 	endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, now.UTC().Location())
// 	secondsUntilEndOfDay := endOfDay.Sub(now).Seconds()
// 	fmt.Println("secondsUntilEndOfDay ", secondsUntilEndOfDay)
// 	fmt.Println("=====", int64(secondsUntilEndOfDay))
// 	fmt.Println("=&7&&&&& :: ", int64(math.Round(secondsUntilEndOfDay)))

// Split vise
// Even Odd using GO Thread and Print in sync

// // u1, u2 = 20RS, u3=40% , u4

// type User struct {
// 	ID       string
// 	UserName string
// 	GroupName string
// }

// var {
// 	Equal string
// 	absaluteamount float32
// 	Ratio int
// }

// //QueryParam

// type Expenx struct {
// 	GroupName string
// 	User_ID string
// 	Amount  float32
// 	SplitWith []string   //userID
// 	payment string
// 	split Split
// }

// type Split struct {
// 	User_ID   string
// 	Amount    float32
// 	Percent   string //("%")
// }

// type Tally struct {
// 	User_ID   string
// 	Amount    float32
// 	CredDebit string
// }

// type Statment struct {
// 	Recive Tally
// 	Pay    Tally
// }

// func main() {
// 	log.Println("Start")
// 	user1 := User{
// 		ID:       "user1",
// 		UserName: "Himansu",
// 	}

// 	user2 := User{
// 		ID:       "user2",
// 		UserName: "Gupta",
// 	}

// 	// Enter Expnese
// 	expen := Expenx{
// 		User_ID: "user1",
// 		Amount:  100,
// 	}
// 	EnterExpens()
// }

// func EnterExpens(expenx Expenx) {
// 	log.Println("Enter in EnterExpens", expenx.User_ID)
// 	// "Equal", Ratio, Absulte
// 	 if  Absulte == expenx.payment{
// 		expenx.split.Amount
// 		expenx.split.User_ID
// 	 }

// 	 if  Ratio == expenx.payment{
// 		expenx.split.Amount
// 		expenx.split.User_ID
// 	 }

// 	// whom we have to split with in  Group member (U2,U3,Default(U1))
// 	// Save into DB in Expnec Collection in particular USer
// 	//result :=  amount / len(expenx.SplitWith) + 1

// 	//
// }

// func tallyExpens(userID string) {
// 	// We do Accountitng as per user ID (User)
// 	// If User2 come

// 	statment := Statment{
// 		recive : Tally{

// 		},
// 	}

// }

// func showExpens() (Expenx, error) {
// 	// Get Records from DB
// 	expen := Expenx{
// 		User_ID: "user1",
// 		Amount:  100,
// 	}
// 	return expen, nil
// }

// encryptedText := "oCqS4DASDI25as25DwUOc2bqBVSc3iOm73gbkWi7V0xOKfbgUlxmU09dNTL++635GaSUyXlCJgQ="
// 	ECP := EllipticCurvePoint{
// 		X: "4725612245743019628890338502622615544047682762028997999123473513923104690100560104199176010090311282882774526775424012794467047770643376068647775084445953099",
// 		Y: "4194743607076653462111050584197551534898406062152218519733854793895804030430540488954877922277313919584465614537088980541717565274196741007148351094904620537",
// 	}
// 	decrypt(encryptedText, ECP)
// func decrypt(encText string, input interface{}) {
// 	secret, curvPt, err := generateSecret(input)
// 	if err != nil {
// 		log.Println("failed to generate secret: " + err.Error())
// 	}

// 	log.Println("curvPt :: ", curvPt)

// 	decData, err := DecryptText(encText, secret)
// 	if err != nil {
// 		log.Println("failed to encrypt: " + err.Error())
// 	}

// 	log.Println("decData :: ", decData)
// }

// // DecryptText - To Decrypt text
// func DecryptText(encText string, key []byte) (string, error) {
// 	log.Println("In DecryptTextData")
// 	ciphertext, err := base64.StdEncoding.DecodeString(encText)
// 	if err != nil {
// 		log.Println("Error decoding Text. Error: ", err)
// 		return "", err
// 	}

// 	c, err := aes.NewCipher(key)
// 	if err != nil {
// 		log.Println("Error New Cipher. Error: ", err)
// 		return "", err
// 	}

// 	gcm, err := cipher.NewGCM(c)
// 	if err != nil {
// 		log.Println("Error New GCM. Error: ", err)
// 		return "", err
// 	}

// 	nonceSize := gcm.NonceSize()
// 	if len(ciphertext) < nonceSize {
// 		log.Println("Error invalid nonce length")
// 		return "", nil
// 	}

// 	nonce, enctext := ciphertext[:nonceSize], ciphertext[nonceSize:]
// 	plaintext, err := gcm.Open(nil, nonce, enctext, nil)
// 	if err != nil {
// 		log.Println("Error New GCM. Error: ", err)
// 		return "", err
// 	}
// 	return string(plaintext), nil
// }

// type EllipticCurvePoint struct {
// 	X string `json:"x"`
// 	Y string `json:"y"`
// }
// func generateSecret(input interface{}) ([]byte, EllipticCurvePoint, error) {

// 	var ok bool
// 	PBK, ok := input.(EllipticCurvePoint)
// 	if !ok {
// 		//logger.Error("Invalid input type. Input of type 'EllipticCurvePoint' is expected")
// 		log.Println("invalid input type. Input of type 'EllipticCurvePoint' is expected")
// 	}

// 	dhg := newDHGenerator()
// 	pubb := ecdsa.PublicKey{}
// 	pubb.Curve = elliptic.P521()
// 	pubb.X, ok = new(big.Int).SetString(PBK.X, 10)
// 	if !ok {
// 		log.Println("encrypt: SetString of BigInt failed")
// 	}

// 	pubb.Y, ok = new(big.Int).SetString(PBK.Y, 10)
// 	if !ok {
// 		log.Println("encrypt: SetString of BigInt failed")
// 	}
// 	secret, err := dhg.GenerateSecret(&pubb)
// 	if err != nil {
// 		log.Println("encrypt: Failed to generate secrete: " + err.Error())
// 	}

// 	curvPt := *dhg.GetEllipticCurvePoint()

// 	return secret[:], curvPt, nil
// }

// type DHGenerator struct {
// 	priv *ecdsa.PrivateKey
// 	pub  *ecdsa.PublicKey
// }

// // NewDHGenerator for instantiaon
// func newDHGenerator() *DHGenerator {
// 	dhg := DHGenerator{}
// 	dhg.init()
// 	return &dhg
// }

// func (g *DHGenerator) init() {
// 	_rand := rand.Reader

// 	tPriv, err := ecdsa.GenerateKey(elliptic.P521(), _rand)
// 	if err != nil {
// 		log.Println(" DHGenerator init ", err)
// 	}

// 	g.priv = tPriv
// 	g.pub = &g.priv.PublicKey

// }

// // GetPublicKey to retrive public key
// func (g *DHGenerator) GetPublicKey() *ecdsa.PublicKey {
// 	//g.init()
// 	return g.pub
// }

// // GetEllipticCurvePoint to get ecp
// func (g *DHGenerator) GetEllipticCurvePoint() *EllipticCurvePoint {
// 	return &EllipticCurvePoint{
// 		X: string(g.pub.X.String()),
// 		Y: string(g.pub.Y.String()),
// 	}
// }

// // GenerateSecret to generate secret
// func (g *DHGenerator) GenerateSecret(pubb *ecdsa.PublicKey) ([32]byte, error) {

// 	if pubb == nil {
// 		//logger.Error("Public key can not be empty. Please provide public key.")
// 		return [32]byte{}, errors.New("Public key can not be empty")
// 	}

// 	temp, _ := pubb.Curve.ScalarMult(pubb.X, pubb.Y, g.priv.D.Bytes())

// 	// Here, secret is a x value.
// 	secret, err := g.fixSecretSize(temp.Bytes(), 66)
// 	if err != nil {
// 		return [32]byte{}, err
// 	}

// 	return sha256.Sum256(secret), nil
// }

// // fixSecretSize pads the secret with zeros to make it of desired size.
// // ToDo: Need to keep only one copy of this function. So, need to call the function at bottom
// // from within this function.
// func (g *DHGenerator) fixSecretSize(secret []byte, size int) ([]byte, error) {

// 	if size < 0 {
// 		log.Println("invalid desired secret size")
// 	}

// 	l := len(secret)

// 	if l == size {
// 		return secret, nil
// 	}

// 	if l < size {
// 		sec := make([]byte, size)
// 		copy(sec[size-l:], secret)
// 		return sec, nil
// 	}

// 	return secret[:size], nil
// }
