from crewai import tool

@tool
def test_func():
    return "CrewAI tool works"

print(test_func())
