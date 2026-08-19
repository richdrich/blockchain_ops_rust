import beaker
import pyteal as pt
from algokit_utils import ensure_funded, EnsureBalanceParameters
from algokit_utils.config import config
from beaker import Application, localnet
from beaker.client import ApplicationClient


# Simple application with minimal state
class SimpleState:
    def __init__(self):
        pass

# Create the application
mini = Application("SimpleApp",
                        state=SimpleState(),
                        build_options=beaker.BuildOptions(scratch_slots=False))

@mini.external
def fn(x: pt.abi.Uint64, *, output: pt.abi.Uint64) -> pt.Expr:
    """Function that takes x and returns x*2+1"""
    return pt.Seq(
        output.set(x.get() * pt.Int(2) + pt.Int(1))
    )

# Override the update method to add creator authorization
@mini.update(bare=True, authorize=beaker.Authorize.only(pt.Global.creator_address()))
def update_app():
    """Update handler that only allows creator to update"""
    return pt.Approve()

@mini.delete(bare=True, authorize=beaker.Authorize.only(pt.Global.creator_address()))
def delete_app():
    """Delete handler that only allows creator to update"""
    return pt.Approve()


def demo() -> None:
    config.configure(debug=True)

    # Here we use `localnet` but beaker.client.api_providers can also be used
    # with something like ``AlgoNode(Network.TestNet).algod()``
    algod_client = localnet.get_algod_client()

    acct = localnet.get_accounts().pop()
    print(f"Account address: {acct.address}")
    print(f"Account balance before: {algod_client.account_info(acct.address)['amount']} microAlgos")

    # Create an Application client containing both an algod client and app
    app_client = ApplicationClient(
        client=algod_client, app=mini, signer=acct.signer
    )

    # Create the application on chain, implicitly sets the app id for the app client
    app_id, app_addr, txid = app_client.create()

    print(f"Created App with id: {app_id} and address addr: {app_addr} in tx: {txid}")
    
    # Fund the application account
    parameters = EnsureBalanceParameters(
        account_to_fund=app_addr,
        min_spending_balance_micro_algos=1000000)

    ensure_funded(algod_client, parameters)
    account_balance_after_fund = algod_client.account_info(acct.address)['amount']
    print(f"Account balance after fund: {account_balance_after_fund} microAlgos")
    app_balance_after_fund = algod_client.account_info(app_addr)['amount']
    print(f"Application account balance after fund: {app_balance_after_fund} microAlgos")

    # Test the fn function with different values
    test_values = [0, 1, 5, 10, 100]
    
    for x in test_values:
        result = app_client.call(fn, x=x)
        expected = x * 2 + 1
        actual = result.return_value
        print(f"fn({x}) = {actual}, expected = {expected}")
        assert actual == expected, f"Expected {expected}, got {actual}"

    print("All tests passed!")

if __name__ == "__main__":
    import sys
    
    # Check if 'demo' is passed as a command line argument
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        # Default behavior: write out the data files
        mini_spec = mini.build()
        # print out the results
        
        original_stdout = sys.stdout  # Save a reference to the original standard output
        
        with open('mini_approval.teal', 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            print(mini_spec.approval_program)
        
        sys.stdout = original_stdout  # Reset the standard output to its original value
        
        original_stdout = sys.stdout  # Save a reference to the original standard output

        with open('mini_clear_state.teal', 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            print(mini_spec.clear_program)
        
        sys.stdout = original_stdout  # Reset the standard output to its original value
        
        original_stdout = sys.stdout  # Save a reference to the original standard output

        with open('mini_spec.json', 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            print(mini_spec.to_json())
        
        sys.stdout = original_stdout  # Reset the standard output to its original value
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        print("Data files written: mini_approval.teal, mini_clear_state.teal, mini_spec.json")