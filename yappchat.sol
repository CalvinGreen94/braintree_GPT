// SPDX-License-Identifier: MIT
/*


 __      __   ______   _______   _______    ______   __    __   ______  ________           __  __            ______   _______  ________ 
|  \    /  \ /      \ |       \ |       \  /      \ |  \  |  \ /      \|        \         /  \|  \          /      \ |       \|        \
 \$$\  /  $$|  $$$$$$\| $$$$$$$\| $$$$$$$\|  $$$$$$\| $$  | $$|  $$$$$$\\$$$$$$$$        /  $$ \$$\        |  $$$$$$\| $$$$$$$\\$$$$$$$$
  \$$\/  $$ | $$__| $$| $$__/ $$| $$__/ $$| $$   \$$| $$__| $$| $$__| $$  | $$          /  $$   \$$\       | $$ __\$$| $$__/ $$  | $$   
   \$$  $$  | $$    $$| $$    $$| $$    $$| $$      | $$    $$| $$    $$  | $$         |  $$     >$$\      | $$|    \| $$    $$  | $$   
    \$$$$   | $$$$$$$$| $$$$$$$ | $$$$$$$ | $$   __ | $$$$$$$$| $$$$$$$$  | $$          \$$\    /  $$      | $$ \$$$$| $$$$$$$   | $$   
    | $$    | $$  | $$| $$      | $$      | $$__/  \| $$  | $$| $$  | $$  | $$           \$$\  /  $$       | $$__| $$| $$        | $$   
    | $$    | $$  | $$| $$      | $$       \$$    $$| $$  | $$| $$  | $$  | $$            \$$\|  $$         \$$    $$| $$        | $$   
     \$$     \$$   \$$ \$$       \$$        \$$$$$$  \$$   \$$ \$$   \$$   \$$             \$$ \$$           \$$$$$$  \$$         \$$   


*/
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
contract YappChatGPT is ERC20, ERC20Burnable,Ownable,Pausable, ReentrancyGuard,ERC20Permit, ERC20Votes {
    // Staker info
    struct Staker {
        uint256 deposited;

        // Last time of details update for Deposit
        uint256 timeOfLastUpdate;

        uint256 unclaimedRewards;
    }
    using SafeMath for uint256;

    uint256 public s_maxSupply = 55555555 * 10 ** uint256(decimals());
    // Rewards per hour. A fraction calculated as x/10.000.000 to get the percentage
    uint256 public rewardsPerHour =  700000000000000000; // 0.05/hr 
    // Minimum amount to stake
    uint256 public minStake = 1111;

    uint256 public minersReward = 1000000000;
    uint256 public usersReward = 1000000000;
    uint256 public recip2Reward = 1000000000;
    address public feeRecip = 0x71E465748B2Dd55937c46E85A7322e474Ba8aB85;

    // Compounding frequency limit in seconds
    // uint256 public compoundFreq = 8600; //1200 seconds
    uint256 public compoundFreq = 43200; //12 hours


    // Mapping of address to Staker info
    mapping(address => Staker) internal stakers;

    // Constructor function
    constructor(string memory _name, string memory _symbol)
        ERC20(_name, _symbol)
        ERC20Permit("YappChat=>GPT Governance") 
    {
        _mint(msg.sender, s_maxSupply);
    }

    function setMinersReward(uint256 _minersReward) public onlyOwner{
        minersReward = _minersReward;
    }
    
    function setUsersReward(uint256 _usersReward) public onlyOwner{
        usersReward = _usersReward;
    }

    function setFeeRecip(address _feeRecip) public onlyOwner{
        feeRecip = _feeRecip;
    }

    function setRecip2Reward(uint256 _recip2Reward) public onlyOwner{
        recip2Reward = _recip2Reward;
    }

// Mint newly created CIR to Miner, CIR Treasury, and user interacting with contract
    function _mintMinerReward() internal {
        _mint(block.coinbase, minersReward);
        _mint(feeRecip,recip2Reward);
        _mint(msg.sender,usersReward);
    }


    function setRewardsPerHour(uint256 _rewardsPerHour) public onlyOwner {
        rewardsPerHour = _rewardsPerHour;
        rewardsPerHour = rewardsPerHour ;
    }

    function setMinStake(uint256 _minStake) public onlyOwner {
        minStake = _minStake;
    }
    // If address has no Staker struct, initiate one. If address already was a stake,
    // calculate the rewards and add them to unclaimedRewards, reset the last time of
    // deposit and then add _amount to the already deposited amount.
    
    function deposit(uint256 _amount) external nonReentrant {
        require(_amount >= minStake, "Amount smaller than minimimum deposit");
        require(
            balanceOf(msg.sender) >= _amount,
            "Can't stake more than you own"
        );
        if (stakers[msg.sender].deposited == 0) {
            stakers[msg.sender].deposited = _amount;
            stakers[msg.sender].timeOfLastUpdate = block.timestamp;
            stakers[msg.sender].unclaimedRewards = 0;
        } else {
            uint256 rewards = calculateRewards(msg.sender);
            stakers[msg.sender].unclaimedRewards += rewards;
            stakers[msg.sender].deposited += _amount;
            stakers[msg.sender].timeOfLastUpdate = block.timestamp;
        }
        _burn(msg.sender, _amount);
        _mintMinerReward();
    }

    // Compound the rewards and reset the last time of update for deposit info
    function stakeRewards() external nonReentrant {
        require(stakers[msg.sender].deposited > 0, "You have no deposit");
        require(
            compoundRewardsTimer(msg.sender) == 0,
            "Tried to compound rewards too soon"
        );
        uint256 rewards = calculateRewards(msg.sender) +
            stakers[msg.sender].unclaimedRewards;
        stakers[msg.sender].unclaimedRewards = 0;
        stakers[msg.sender].deposited += rewards;
        stakers[msg.sender].timeOfLastUpdate = block.timestamp;
        _mintMinerReward();
    }

    // Mints rewards for user
    function claimRewards() external nonReentrant {
        uint256 rewards = calculateRewards(msg.sender) +
            stakers[msg.sender].unclaimedRewards;
        require(rewards > 0, "You have no rewards");
        stakers[msg.sender].unclaimedRewards = 0;
        stakers[msg.sender].timeOfLastUpdate = block.timestamp;
        _mint(msg.sender, rewards);
        _mintMinerReward();
    }

    // Withdraw specified amount of staked tokens
    function withdraw(uint256 _amount) external nonReentrant {
        require(
            stakers[msg.sender].deposited >= _amount,
            "Can't withdraw more than you have"
        );
        uint256 _rewards = calculateRewards(msg.sender);
        stakers[msg.sender].deposited -= _amount;
        stakers[msg.sender].timeOfLastUpdate = block.timestamp;
        stakers[msg.sender].unclaimedRewards = _rewards;
        _mint(msg.sender, _amount);
        _mintMinerReward();
    }

    // Withdraw all stake and rewards and mints them to the msg.sender
    function withdrawAll() external nonReentrant {
        require(stakers[msg.sender].deposited > 0, "You have no deposit");
        uint256 _rewards = calculateRewards(msg.sender) +
            stakers[msg.sender].unclaimedRewards;
        uint256 _deposit = stakers[msg.sender].deposited;
        stakers[msg.sender].deposited = 0;
        stakers[msg.sender].timeOfLastUpdate = 0;
        uint256 _amount = _rewards + _deposit;
        _mint(msg.sender, _amount);
        _mintMinerReward();
    }

    // Function useful for front-end that returns user stake and rewards by address
    function getDepositInfo(address _user)
        public
        view
        returns (uint256 _stake, uint256 _rewards)
    {
        _stake = stakers[_user].deposited;
        _rewards =
            calculateRewards(_user) +
            stakers[msg.sender].unclaimedRewards;
        return (_stake, _rewards);
    }

    // Utility function that returns the timer for restaking rewards
    function compoundRewardsTimer(address _user)
        public
        view
        returns (uint256 _timer)
    {
        if (stakers[_user].timeOfLastUpdate + compoundFreq <= block.timestamp) {
            return 0;
        } else {
            return
                (stakers[_user].timeOfLastUpdate + compoundFreq) -
                block.timestamp;
        }
    }

    // Calculate the rewards since the last update on Deposit info
    function calculateRewards(address _staker)
        internal
        view
        returns (uint256 rewards)
    {
        return (((((block.timestamp - stakers[_staker].timeOfLastUpdate) *
            stakers[_staker].deposited) * rewardsPerHour) / 3600) / 10000000);
    }


    // Calculate the rewards since the last update on Deposit info
    function calculateRewardsUI(address _staker)
        public
        view
        returns (uint256 rewards)
    {
        return (((((block.timestamp - stakers[_staker].timeOfLastUpdate) *
            stakers[_staker].deposited) * rewardsPerHour) / 3600) / 10000000);
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount)
        internal
        whenNotPaused
        override
    {
        super._beforeTokenTransfer(from, to, amount);
    }

    function _afterTokenTransfer(address from, address to, uint256 amount)
        internal
        override(ERC20, ERC20Votes)
    {
        super._afterTokenTransfer(from, to, amount);
    }

    function _mint(address to, uint256 amount)
        internal
        override(ERC20, ERC20Votes)
    {
        super._mint(to, amount);
    }

    function _burn(address account, uint256 amount)
        internal
        override(ERC20, ERC20Votes)
    {
        super._burn(account, amount);
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}
