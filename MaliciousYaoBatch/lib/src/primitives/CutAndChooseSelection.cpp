#include "../../include/primitives/CutAndChooseSelection.hpp"

void CutAndChooseSelection::doConstruct(vector<byte>& selection, int numCheck)
{
	// set the selection array and size.
	this->selection = selection;
	numCircuits = selection.size();

	//Create a set of circuits and push the checked and evaluate circuit to the appropriate place.
	checkCircuits.resize(numCheck);
	evalCircuits.resize(numCircuits - numCheck);

	int checkIndx = 0;
	int evalIndx = 0;
	for (size_t i = 0; i < numCircuits; i++)
	{
		//check binary
		assert((0 <= selection[i]) && (selection[i] <= 1));

		if (1 == selection[i])
		{
			checkCircuits[checkIndx] = i;
			checkIndx++;
		}
		else
		{
			evalCircuits[evalIndx] = i;
			evalIndx++;
		}
	}
}

CutAndChooseSelection::CutAndChooseSelection(vector<byte>& selection)
{
	//find the number of checked circuits
	int sum = 0;
	auto size = selection.size();
	for (size_t i = 0; i < size; i++)
	{
		sum += selection[i];
	}

	doConstruct(selection, sum);
}
