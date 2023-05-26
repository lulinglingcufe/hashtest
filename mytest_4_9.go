package main

import (
	 "fmt"
	"math"
	"bytes"
	"encoding/gob"	
	"os"
	"math/rand"
	 merkletree "github.com/wealdtech/go-merkletree"
	 "github.com/wealdtech/go-merkletree/keccak256"
	 "time"
	 "strconv"
)


const _letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const _letterslen = len(_letters)

func _randomString(n int) string {
	res := make([]byte, n)
	for i := range res {
		res[i] = _letters[rand.Int63()%int64(_letterslen)]
	}
	return string(res)
}

// Example using the Merkle tree to generate and verify proofs.
func main() {
	var indices=[519]uint64{1493,1536,1883,2148,2546,2657,2914,3164,3440,3591,4174,4559,4580,4780,4786,5023,5030,5316,5405,5541,6073,6095,6654,6737,6790,6868,7126,7405,8527,8604,8745,8815,9118,9125,9175,9211,9789,10462,11198,11330,11460,12210,12706,12711,12780,12879,13113,13226,13913,15313,15458,18923,19006,19271,19318,19376,19971,20632,21090,21562,21635,21833,21846,22682,22995,23026,24408,25765,26071,28059,28067,28073,28131,28152,28237,28239,28262,28676,30399,32558,32745,33095,33447,33464,33466,33874,34313,34478,34596,34605,34923,35237,35282,35370,35402,35542,35547,35685,35801,36916,37164,37233,37529,38133,38157,38228,38238,38313,38343,38441,38457,39153,39196,39380,39484,40199,41430,41882,42028,42860,43479,45388,45854,46304,46372,46452,46927,47895,48944,49222,49848,49930,50208,50271,50279,50315,50321,50466,50518,50549,50618,50673,51495,52893,52968,53117,53135,53892,54807,55193,55439,55737,56273,56707,56734,57472,57859,59104,59388,59444,59749,60783,60906,60907,61429,61586,61978,61999,62080,62186,62413,62414,62490,62492,64089,64260,65318,66075,66095,66216,66236,66329,66401,66488,67147,67334,68051,68841,69808,70519,70541,71016,71236,71255,71426,71585,72306,72745,73349,73406,73414,73429,73655,73686,74067,74180,74453,74504,74650,74675,75026,75105,75115,75246,75488,75552,76060,76233,77252,77627,77844,78080,78089,78135,78185,78266,78295,78582,78818,78898,79301,79536,79898,79915,79976,80013,80027,80318,80525,81566,82704,83078,83176,84121,84246,85546,86121,86176,86207,86273,86382,86517,86646,86672,87145,87586,87588,87647,88189,89036,89128,89230,89420,89772,89805,89930,90372,90720,90828,91970,92179,92183,92201,92207,92370,92575,92632,92869,98087,98802,99373,99694,99790,99835,100471,100478,100655,100917,101886,102121,102611,103381,104631,105460,105479,106771,106789,107803,107993,109949,111230,111243,111504,111531,111873,111946,112091,112379,112417,112491,112570,112656,112792,112922,113058,113159,113722,113836,114901,115534,116133,116468,116668,116750,117267,117449,118603,118648,119253,120085,120187,120473,120713,121990,122138,122142,122147,122169,122255,122412,122712,122939,123319,124469,125092,125500,126558,126924,126970,127232,127454,127703,128028,128782,129711,129865,129873,130090,130211,130662,130879,131596,131874,132075,134490,135160,135685,135969,136336,136447,137079,137086,137098,137287,137303,137757,138724,138981,139541,139782,139822,140142,140489,140631,141127,141185,141210,141295,141643,141694,141802,142144,142319,142372,142603,143371,143958,147017,147145,148045,148781,149230,149689,150756,151537,151695,152601,152603,154719,154748,154770,158277,159293,160738,161982,162036,162225,162618,163273,163585,163631,164811,165137,165386,166488,166627,166788,167232,167425,167985,168422,168451,168498,168832,170965,172463,172999,173407,173489,174789,175819,175984,176162,176336,176640,176811,177099,177148,177281,177591,178068,178349,178459,180726,182737,182757,182910,184128,184382,184400,184554,184674,184802,185535,185665,185912,185915,186443,186503,187398,187887,188531,189014,189330,189540,189608,189839,189842,189870,190012,190053,190746,190848,192349,192419,192847,193310,193381,193709,193796,194013,194137,194394,194469,194638,194942,195270,195504,195613,195696,195738,195800,195824,196103,196700,196708,196762,196769,196884,197054,197218,197409,198042,198157,198202,198249,198260,198279,199107}


   //我给出了indice。但是需要把这个indices按照。首先我需要对indice进行划分。这样才能找到合适的分片tree。
   //我们假设：在遍历C++ set的时候，已经对indice进行划分了。indice访问的树编号，放在一个列表里面。一个树里面的indice节点，放在一个list里面。



    var total_indices_number int =519 //indices的长度
	var  dataItems int = 200000//4096 1000000
	var  shard_granularity uint64 = 10000  // 200000 //分片粒度 5000   10000   5000 20000 5000

	//proofs := 10//1234//291   查询位置的数量
	data := make([][]byte, dataItems) //数据初始化
	for i := 0; i < dataItems; i++ {
		data[i] = []byte(_randomString(700))
	}

	var indice_tree_number []uint64 //indice的分片树编号
	//indice_tree_number := make([]uint64, shard_number)
	//indice_tree_number[1]=0
	var per_tree_indices [][]uint64 //indice的分片树某个编号中的indices
	//per_tree_indices := make([][]uint64, shard_number)
	// var test1=[]uint64{1,2,3}
	// per_tree_indices = append(per_tree_indices, test1)

    //通过set的遍历，把 indice_tree_number 和 per_tree_indices 初始化好。
    //首先要找到第一颗树的范围。
    var  tree_number uint64 = uint64(math.Floor(float64(indices[0])/float64(shard_granularity)))
	//分片树的编号
	var bound uint64 = shard_granularity*(1+tree_number)//分片树编号代表的节点范围
	var indice_number int = 0   //分片中indice的数量
	indice_tree_number = append(indice_tree_number, tree_number)

	//var total_element_number int = 0
	for i := 0; i < total_indices_number; i++ { //1234
		if(indices[i]< bound ){
			indice_number++
			//fmt.Printf("This is indice_number++ : %v \n",indice_number)

			if(i == (total_indices_number-1)){ //遍历到最后一个indice元素，且没有增加新的树范围：
				copyData := make([]uint64, indice_number)  //初始化切片数组
				copy(copyData, indices[i+1-indice_number:])//复制切片数组
				//fmt.Printf("This is indices[i-indice_number+1:i] : %v %v \n",i+1-indice_number,i)
				per_tree_indices = append(per_tree_indices, copyData)//把数组放到 per_tree_indices 里面
				//total_element_number = total_element_number + indice_number
				//fmt.Printf("This is indice_number : %v \n",indice_number)
			}

		} else {
			//遍历到最后一个indice元素，需要增加新的树范围：
			if(i == (total_indices_number-1)){ 
            //(1)把前面的数据放好。 
			copyData := make([]uint64, indice_number)  //初始化切片数组
			copy(copyData, indices[i-indice_number:i])//复制切片数组
			per_tree_indices = append(per_tree_indices, copyData)//把数组放到 per_tree_indices 里面


			//(2)重新确定下一个元素所在的分片树的编号
			tree_number = uint64(math.Floor(float64(indices[i])/float64(shard_granularity)))
			indice_tree_number = append(indice_tree_number, tree_number)
			indice_number = 1
			//把自己放入下一个分片树的数据里面。
			copyData2 := make([]uint64, indice_number)  //初始化切片数组
			copyData2[0] = indices[i]
			per_tree_indices = append(per_tree_indices, copyData2)//把数组放到 per_tree_indices 里面

			} else { 
			//不是最后一个元素。
			copyData := make([]uint64, indice_number)  //初始化切片数组
			copy(copyData, indices[i-indice_number:i])//复制切片数组
			//fmt.Printf("This is indices[i-indice_number:i] : %v %v \n",i-indice_number,i)
			per_tree_indices = append(per_tree_indices, copyData)//把数组放到 per_tree_indices 里面

			tree_number = uint64(math.Floor(float64(indices[i])/float64(shard_granularity)))
			//重新确定下一个元素所在的分片树的编号
			indice_tree_number = append(indice_tree_number, tree_number)
			//把 分片树的编号放到 indice_tree_number里面。

			// fmt.Printf("This is tree_number : %v \n",tree_number)
			// fmt.Printf("This is indice_tree_number : %v \n",indice_tree_number)
			bound = shard_granularity*(1+tree_number)
			//fmt.Printf("This is bound : %v \n",bound)
			//total_element_number = total_element_number + indice_number
			indice_number = 1
			//fmt.Printf("This is indice_number : %v \n",indice_number)
		}

		}


	}
    
	//var total_element_number int = 0
	for i, copyData := range per_tree_indices {
		decrese_for_all_element := indice_tree_number[ indice_tree_number[i] ]*shard_granularity
		//每个元素要减去相应的：树编号*分片粒度
        for j := range copyData{
			copyData[j] = copyData[j]-decrese_for_all_element
			//total_element_number++
		}
	  }


	// fmt.Printf("This is indice_tree_number : %v \n",indice_tree_number)
	// fmt.Printf("This is per_tree_indices : %v \n",per_tree_indices)

	//fmt.Printf("This is total_element_number : %v \n",total_element_number)


    //构造hash tree，这个是一开始create index之后就要做的事情。
	//如果进行分片，那么需要构造 多棵树。我用一个列表 tree_ptr 放这些树。
	shard_number  := uint64(math.Ceil( float64(dataItems)/float64(shard_granularity))) //分片的组数
	tree_ptr := make([]*merkletree.MerkleTree, shard_number)

	var temp_j uint64 = 0
	for j := temp_j; j < shard_number; j++ {
		tree, err := merkletree.NewUsing(data[j* shard_granularity:(j+1)* shard_granularity],keccak256.New(), false)
		if err != nil {
			panic(err)
		}
		tree_ptr[j] = tree
		//fmt.Printf("This is j : %v \n",j)
	}


   start := time.Now() // 获取当前时间：SP生成VO开始计时
   indice_proof_number := make([]int, len(indice_tree_number)) //indice的分片树proof中的byte数量

   //这里需要构造一个循环。对每一个 indice数组 构造VO。
   for i, copyData := range per_tree_indices {
	//对于第i个indice数组
	increase_for_all_element := indice_tree_number[ indice_tree_number[i] ]*shard_granularity

	//(1) 每个元素要加上相应的：树编号*分片粒度，从而得到proofdata的位置
	proofData := make([][]byte, len(copyData) )
	//copyData就是{1,2,3}的indice数组。
    
	//（2）按照copyData生成proofData
	for j := 0; j < len(copyData); j++ {
		//fmt.Printf("This is copyData[j] + increase_for_all_element : %v \n",copyData[j]   +  increase_for_all_element)
		proofData[j] = data[ copyData[j]   +  increase_for_all_element ]
	}
	
	// fmt.Printf("This is i : %v \n",i)
	// fmt.Printf("This is increase_for_all_element : %v \n",increase_for_all_element)
    //（3）生成multiProof
	multiProof, err := tree_ptr[i].GenerateMultiProof(proofData)
	if err != nil {
		fmt.Println("tree_ptr[i].GenerateMultiProof failure ", err.Error())
		return
	}
	//fmt.Printf("This is multiProof : %x \n", multiProof)

    //（4）把 multiProof 写入到 文件中。
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	enc.Encode(multiProof)
	i_str := strconv.Itoa(i)
    s := "hnswvo/output.bin_" + i_str
    file, err := os.Create(s) //这里要按照循环次数，进行命名 "output.bin"

	if err != nil {
		fmt.Println("File creation failure ", err.Error())
		return
	}
	defer file.Close() 
	b_bytes := b.Bytes()
	indice_proof_number[i] = len(b_bytes)  //把proof的byte长度存储到一个数组中
	//fmt.Printf("This is b_bytes len : %v \n",len(b_bytes))

	_, err = file.Write(b_bytes)
	if err != nil {
		fmt.Println("Encoding failure", err.Error())
		return
	}
  }


	elapsed := time.Since(start)
    fmt.Println("VO generate and sotre Time : ", elapsed)
	
	////读取VO


	start_read := time.Now() // 获取当前时间：用户验证VO开始计时
   //通过一个循环来读取VO。
   for i, copyData := range per_tree_indices {

	//start_read_proof := time.Now() 
	//对于第i个indice数组
	increase_for_all_element := indice_tree_number[ indice_tree_number[i] ]*shard_granularity
	//(1) 每个元素要加上相应的：树编号*分片粒度，从而得到proofdata的位置
	proofData := make([][]byte, len(copyData) )
	//copyData就是{1,2,3}的indice数组。
    
	//（2）按照copyData生成proofData
	for j := 0; j < len(copyData); j++ {
		//fmt.Printf("This is copyData[j] + increase_for_all_element : %v \n",copyData[j]   +  increase_for_all_element)
		proofData[j] = data[ copyData[j]   +  increase_for_all_element ]
	}
	
	// read_proof_elapsed := time.Since(start_read_proof)
    // fmt.Println("read_proof_elapsed Time in VO verfiy : ", read_proof_elapsed)


    //(3)读取第i个proof文件
	i_str := strconv.Itoa(i)
    s := "hnswvo/output.bin_" + i_str
	file_read, err := os.Open(s)
    defer file_read.Close()
	b_bytes_length := indice_proof_number[i]
	tmp_read_bytes := make([]byte, b_bytes_length)  //当时存储进文件的bytes长度
	_, err = file_read.Read(tmp_read_bytes)
	if err != nil {
		fmt.Println("Read file failure", err.Error())
		return
	}
	//（4）用proof文件生成MultiProof
	var b_read bytes.Buffer
	b_read.Write(tmp_read_bytes) //把读取出来的bytes写入buffer缓冲区
	dec := gob.NewDecoder(&b_read)
	var test_read_data merkletree.MultiProof
	err = dec.Decode(&test_read_data)
	if err != nil {
		fmt.Println("Error decoding GOB data:", err)
		return
	}
	//fmt.Printf("This is multiProof test_data : %x \n",test_read_data)

    //（5）client验证VO。 proofData就是:朋友+节点的信息。
	proven, err := merkletree.VerifyMultiProofUsing(proofData, false, &test_read_data, tree_ptr[i].Root(),keccak256.New())
	fmt.Printf("This is proven : %v \n",proven)
  }

	read_elapsed := time.Since(start_read)
    fmt.Println("VO read and verfiy Time : ", read_elapsed)








	// start := time.Now() // 获取当前时间（SP生成VO）

	// indices := make([]uint64, proofs)
	// proofData := make([][]byte, proofs)


	// for j := 0; j < proofs; j++ {
	// 	//indices[j] = uint64(rand.Int31n(int32(dataItems)))
	// 	proofData[j] = data[indices[j]]
	// }

	// //start := time.Now()
    // //SP生成VO。
	// multiProof, err := tree.GenerateMultiProof(proofData)
	// //multiProof, err := tree_ptr[1].GenerateMultiProof(proofData)


	// //fmt.Printf("This is multiProof : %x \n",multiProof)
	// // elapsed := time.Since(start)
    // // fmt.Println("VO generate Time : ", elapsed)
	
	// ////把VO写入文件。

	// //start_write := time.Now()
	// var b bytes.Buffer
	// enc := gob.NewEncoder(&b)
	// enc.Encode(multiProof)
    // file, err := os.Create("output.bin")
	// if err != nil {
	// 	fmt.Println("File creation failure ", err.Error())
	// 	return
	// }
	// defer file.Close() 
	// b_bytes := b.Bytes()
	// //fmt.Printf("This is b_bytes len : %v \n",len(b_bytes))

	// _, err = file.Write(b_bytes)
	// if err != nil {
	// 	fmt.Println("Encoding failure", err.Error())
	// 	return
	// }
	// // elapsed_write := time.Since(start_write)
    // // fmt.Println("VO sotre Time : ", elapsed_write)
	// elapsed := time.Since(start)
    // fmt.Println("VO generate and sotre Time : ", elapsed)
	
	
	// ////读取VO
	// start_read := time.Now() // 获取当前时间

	// file_read, err := os.Open("output.bin")
    // defer file_read.Close()
	// tmp_read_bytes := make([]byte, len(b_bytes))
	// _, err = file_read.Read(tmp_read_bytes)
	// if err != nil {
	// 	fmt.Println("Read file failure", err.Error())
	// 	return
	// }
	// var b_read bytes.Buffer
	// b_read.Write(tmp_read_bytes) //把读取出来的bytes写入buffer缓冲区
	// dec := gob.NewDecoder(&b_read)
	// var test_read_data merkletree.MultiProof
	// err = dec.Decode(&test_read_data)
	// if err != nil {
	// 	fmt.Println("Error decoding GOB data:", err)
	// 	return
	// }
	// //fmt.Printf("This is multiProof test_data : %x \n",test_read_data)

    // //client验证VO。 proofData就是在获取朋友+节点的信息。
	// proven, err := merkletree.VerifyMultiProofUsing(proofData, false, multiProof, tree.Root(),keccak256.New())
	// //proven, err := merkletree.VerifyMultiProofUsing(proofData, false, &test_data, tree.Root(),keccak256.New())
	
	// //VerifyMultiProofUsing([][]byte{data}, false, proof, tree.Root(), test.hashType)
	// //merkletree.VerifyMultiProof(proofData, false, multiProof, tree.Root())
	// fmt.Printf("This is proven : %v \n",proven)

	// read_elapsed := time.Since(start_read)
    // fmt.Println("VO read and verfiy Time : ", read_elapsed)
	
	// // // Data for the tree
	// // data := [][]byte{
	// // 	[]byte("Foossssssssssssssssssssssssssssssssssssssssssssss"),
	// // 	[]byte("Bar"),
	// // 	[]byte("Baz"),
	// // }

	// // // Create the tree
	// // //tree, err := merkletree.NewUsing(data, keccak256.New(), false)
	// // tree, err := merkletree.NewUsing(data, keccak256.New(), false)
	// // if err != nil {
	// // 	panic(err)
	// // }

	// // // Fetch the root hash of the tree
	// // root := tree.Root()

	// // baz := data[2]
	// // // Generate a proof for 'Baz'
	// // proof, err := tree.GenerateProof(baz, 0)//
	// // if err != nil {
	// // 	panic(err)
	// // }
	// // fmt.Printf("This is proof :%v \n",proof)

	// // // Verify the proof for 'Baz'
	// // verified, err := merkletree.VerifyProof(baz, false, proof, [][]byte{root})
	// // if err != nil {
	// // 	panic(err)
	// // }
	// // if !verified {
	// // 	panic("failed to verify proof for Baz")
	// // }
	// // fmt.Printf("This is verify : %v \n",verified)
}
