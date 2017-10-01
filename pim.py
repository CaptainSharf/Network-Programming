import random
def pim(inputdictionary):
	roundno=0
	while len(inputdictionary)>0:
		inversedictionary={}
		keys = inputdictionary.keys()
		for i in keys:
			for j in inputdictionary[i]:
				try:
					inversedictionary[j].append(i)
				except KeyError:
					inversedictionary[j]=[i]
			if len(inputdictionary[i])==0:
				inputdictionary.pop(i,None)
		iterno=0
		while(len(inversedictionary)>0):
			doubleinverse={}
			keys=inversedictionary.keys()
			for i in keys:
				ind=random.randint(0,len(inversedictionary[i])-1)
				try:
					doubleinverse[inversedictionary[i][ind]].append(i)
				except KeyError:
					doubleinverse[inversedictionary[i][ind]]=[i]
			keys=doubleinverse.keys()
			for i in keys:
				if len(doubleinverse[i])>1:
					ind=random.randint(0,len(doubleinverse[i])-1)
					doubleinverse[i]=[doubleinverse[i][ind]]
				inversedictionary.pop(doubleinverse[i][0],None)
				# print doubleinverse[i]
			for j in inversedictionary.keys():
				for i in keys:
					try:
						inversedictionary[j].remove(i)
					except ValueError:
						pass
				if len(inversedictionary[j])==0:
					inversedictionary.pop(j,None)
			for i in keys:
				inputdictionary[i].remove(doubleinverse[i][0])
				if len(inputdictionary[i])==0:
					inputdictionary.pop(i,None)
			iterno=iterno+1
		roundno=roundno+1
		print roundno,iterno
	return roundno

# inputdictionary={1:[1,2,3,4],2:[2],3:[3],4:[4]}
inputdictionary={1:[1,2,3,4,5,6,7,8],2:[2,3,4,1,5,8,7,6],3:[1,3,5,7,2,4,6,8],4:[1,2,5,7,8,3,4,6],
5:[3,5,7,8,1,2,4,6],6:[1,2,3,4,5,6,7,8],7:[2,4,6,8,1,3,5,7],8:[8,6,7,1,2,3,5,4]}
# inputdictionary={1:[1,2,3,4,5,6,7,8],2:[3],3:[3],4:[5],5:[5],6:[7],7:[7],8:[]}
rpim = pim(inputdictionary)
print rpim