/**
 *Submitted for verification at polygonscan.com on 2023-12-28
*/

// Dependency file: openzeppelin-solidity/contracts/cryptography/ECDSA.sol

// SPDX-License-Identifier: MIT

// pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Check the signature length
        if (signature.length != 65) {
            revert("ECDSA: invalid signature length");
        }

        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        return recover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover-bytes32-bytes-} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "ECDSA: invalid signature 's' value");
        require(v == 27 || v == 28, "ECDSA: invalid signature 'v' value");

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");

        return signer;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * replicates the behavior of the
     * https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign[`eth_sign`]
     * JSON-RPC method.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}


// Dependency file: openzeppelin-solidity/contracts/utils/Context.sol


// pragma solidity >=0.6.0 <0.8.0;

/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with GSN meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}


// Dependency file: openzeppelin-solidity/contracts/token/ERC20/IERC20.sol


// pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}


// Dependency file: openzeppelin-solidity/contracts/math/SafeMath.sol


// pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        uint256 c = a + b;
        if (c < a) return (false, 0);
        return (true, c);
    }

    /**
     * @dev Returns the substraction of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b > a) return (false, 0);
        return (true, a - b);
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) return (true, 0);
        uint256 c = a * b;
        if (c / a != b) return (false, 0);
        return (true, c);
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a / b);
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a % b);
    }

    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: modulo by zero");
        return a % b;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {trySub}.
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        return a - b;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryDiv}.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        return a / b;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting with custom message when dividing by zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryMod}.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        return a % b;
    }
}


// Dependency file: openzeppelin-solidity/contracts/token/ERC20/ERC20.sol


// pragma solidity >=0.6.0 <0.8.0;

// import "openzeppelin-solidity/contracts/utils/Context.sol";
// import "openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";
// import "openzeppelin-solidity/contracts/math/SafeMath.sol";

/**
 * @dev Implementation of the {IERC20} interface.
 *
 * This implementation is agnostic to the way tokens are created. This means
 * that a supply mechanism has to be added in a derived contract using {_mint}.
 * For a generic mechanism see {ERC20PresetMinterPauser}.
 *
 * TIP: For a detailed writeup see our guide
 * https://forum.zeppelin.solutions/t/how-to-implement-erc20-supply-mechanisms/226[How
 * to implement supply mechanisms].
 *
 * We have followed general OpenZeppelin guidelines: functions revert instead
 * of returning `false` on failure. This behavior is nonetheless conventional
 * and does not conflict with the expectations of ERC20 applications.
 *
 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.
 * This allows applications to reconstruct the allowance for all accounts just
 * by listening to said events. Other implementations of the EIP may not emit
 * these events, as it isn't required by the specification.
 *
 * Finally, the non-standard {decreaseAllowance} and {increaseAllowance}
 * functions have been added to mitigate the well-known issues around setting
 * allowances. See {IERC20-approve}.
 */
contract ERC20 is Context, IERC20 {
    using SafeMath for uint256;

    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;
    uint8 private _decimals;

    /**
     * @dev Sets the values for {name} and {symbol}, initializes {decimals} with
     * a default value of 18.
     *
     * To select a different value for {decimals}, use {_setupDecimals}.
     *
     * All three of these values are immutable: they can only be set once during
     * construction.
     */
    constructor (string memory name_, string memory symbol_) public {
        _name = name_;
        _symbol = symbol_;
        _decimals = 18;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5,05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the value {ERC20} uses, unless {_setupDecimals} is
     * called.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view virtual returns (uint8) {
        return _decimals;
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}.
     */
    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Requirements:
     *
     * - `recipient` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    /**
     * @dev See {IERC20-transferFrom}.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the EIP. See the note at the beginning of {ERC20}.
     *
     * Requirements:
     *
     * - `sender` and `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     * - the caller must have allowance for ``sender``'s tokens of at least
     * `amount`.
     */
    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }

    /**
     * @dev Atomically decreases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `spender` must have allowance for the caller of at least
     * `subtractedValue`.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));
        return true;
    }

    /**
     * @dev Moves tokens `amount` from `sender` to `recipient`.
     *
     * This is internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance");
        _balances[recipient] = _balances[recipient].add(amount);
        emit Transfer(sender, recipient, amount);
    }

    /** @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     */
    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, reducing the
     * total supply.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens.
     */
    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance");
        _totalSupply = _totalSupply.sub(amount);
        emit Transfer(account, address(0), amount);
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.
     *
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     */
    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @dev Sets {decimals} to a value other than the default one of 18.
     *
     * WARNING: This function should only be called from the constructor. Most
     * applications that interact with token contracts will not expect
     * {decimals} to ever change, and may work incorrectly if it does.
     */
    function _setupDecimals(uint8 decimals_) internal virtual {
        _decimals = decimals_;
    }

    /**
     * @dev Hook that is called before any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be to transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }
}


// Dependency file: src/IRelayRecipient.sol

// pragma solidity >=0.6.0;

/**
 * a contract must implement this interface in order to support relayed transaction.
 * It is better to inherit the BaseRelayRecipient as its implementation.
 */
abstract contract IRelayRecipient {

    /**
     * return if the forwarder is trusted to forward relayed transactions to us.
     * the forwarder is required to verify the sender's signature, and verify
     * the call is not a replay.
     */
    function isTrustedForwarder(address forwarder) public virtual pure returns(bool);

    /**
     * return the sender of this call.
     * if the call came through our trusted forwarder, then the real sender is appended as the last 20 bytes
     * of the msg.data.
     * otherwise, return `msg.sender`
     * should be used in the contract anywhere instead of msg.sender
     */
    function _msgSender() internal virtual view returns (address payable);

    function versionRecipient() external virtual view returns (string memory);
}

// Dependency file: src/BaseRelayRecipient.sol

// import 'src/IRelayRecipient.sol';

// pragma solidity 0.6.12;

// Source:
// https://github.com/opengsn/gsn/blob/995647ebf8e34ac183d5b99c06c385bc1995d6dd/packages/contracts/src/BaseRelayRecipient.sol
// With payable modified reinstated, msgData removed

/**
 * A base contract to be inherited by any contract that want to receive relayed transactions
 * A subclass must use "_msgSender()" instead of "msg.sender"
 */
abstract contract BaseRelayRecipient is IRelayRecipient {

    function isTrustedForwarder(address forwarder) public override pure returns(bool) {
        return forwarder == 0x86C80a8aa58e0A4fa09A69624c31Ab2a6CAD56b8;
    }

    /**
     * return the sender of this call.
     * if the call came through our trusted forwarder, return the original sender.
     * otherwise, return `msg.sender`.
     * should be used in the contract anywhere instead of msg.sender
     */
    function _msgSender() internal override virtual view returns (address payable ret) {
        if (msg.data.length >= 20 && isTrustedForwarder(msg.sender)) {
            // At this point we know that the sender is a trusted forwarder,
            // so we trust that the last bytes of msg.data are the verified sender address.
            // extract sender address from the end of msg.data
            assembly {
                ret := shr(96,calldataload(sub(calldatasize(),20)))
            }
        } else {
            return msg.sender;
        }
    }
}


// Dependency file: src/StringParser.sol

// import '/Users/chejazi/Projects/Cent/aib-contracts/node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol';

// pragma solidity ^0.6.0;

library StringParser {
	using SafeMath for uint256;

	function _asciiBase16ToAddress(
        string memory ascii
    ) internal pure returns (address) {
        uint256 result = 0;
        bytes memory asciiBytes = bytes(ascii);
        require(asciiBytes.length == 42, "Invalid address");
        for (uint i = 2; i < asciiBytes.length; i++) {
            uint256 char = uint256(uint8(asciiBytes[i]));
            if (char >= 48 && char <= 57) {
                char -= 48; // 0-9
            }
            else if (char >= 65 && char <= 70) {
                char -= 55; // A-F
            }
            else if (char >= 97 && char <= 102) {
                char -= 87; // a-f
            }
            else {
                revert("Invalid address");
            }
            result = result.mul(16).add(char);
        }
        return address(result);
    }

    function _asciiBase10ToUint(
        string memory ascii
    ) internal pure returns (uint256) {
        uint256 result = 0;
        bytes memory asciiBytes = bytes(ascii);
        for (uint i = 0; i < asciiBytes.length; i++) {
            uint256 digit = uint256(uint8(asciiBytes[i])) - 48;
            require(digit >= 0 && digit <= 9, "Invalid number");
            result = result.mul(10).add(digit);
        }
        return result;
    }
}


// Dependency file: src/StreakPointsToken.sol

// import '/Users/chejazi/Projects/Cent/aib-contracts/node_modules/openzeppelin-solidity/contracts/cryptography/ECDSA.sol';
// import '/Users/chejazi/Projects/Cent/aib-contracts/node_modules/openzeppelin-solidity/contracts/token/ERC20/ERC20.sol';
// import 'src/BaseRelayRecipient.sol';
// import 'src/StringParser.sol';

// pragma solidity ^0.6.0;

contract StreakPointsToken is ERC20, BaseRelayRecipient {
    string public constant override versionRecipient = '1';

    address private nominatedAdmin;
    address private admin;
    mapping(address => bool) private games;

    constructor() public ERC20('StreakPoints', 'SP')  {
        admin = _msgSender();
    }

    function mint(address to, uint amount) external {
        require(games[_msgSender()], 'Game not registered');
        _mint(to, amount);
    }

    function burn(uint amount) external {
        _burn(_msgSender(), amount);
    }

    function addGame(address game) external {
        require(_msgSender() == admin, 'Not Admin');

        games[game] = true;
    }

    function removeGame(address game) external {
        require(_msgSender() == admin, 'Not Admin');

        games[game] = false;
    }

    function nominateAdmin(address nominee) external {
        require(_msgSender() == admin, 'Not Admin');

        nominatedAdmin = nominee;
    }

    function acceptAdmin() external {
        require(_msgSender() == nominatedAdmin, 'Admin not nominated');

        admin = _msgSender();
        nominatedAdmin = address(0);
    }

    function getAddressIsGame(address game) external view returns (bool) {
        return games[game];
    }

    function getAdmin() external view returns (address) {
        return admin;
    }

    function _msgSender() internal override(Context, BaseRelayRecipient) view returns (address payable) {
        return BaseRelayRecipient._msgSender();
    }
}


// Root file: src/StreakPointsGame.sol

// import '/Users/chejazi/Projects/Cent/aib-contracts/node_modules/openzeppelin-solidity/contracts/cryptography/ECDSA.sol';
// import '/Users/chejazi/Projects/Cent/aib-contracts/node_modules/openzeppelin-solidity/contracts/token/ERC20/ERC20.sol';
// import 'src/BaseRelayRecipient.sol';
// import 'src/StringParser.sol';
// import 'src/StreakPointsToken.sol';

pragma solidity ^0.6.0;

contract StreakPointsGame is Context, BaseRelayRecipient {
    string public constant override versionRecipient = '1';

    struct Account {
        uint points;
        uint currentStreak;
        uint longestStreak;
        uint lastCheckinEpoch;
        uint lastCheckinPoints;
    }

    uint private constant BITMASK_32 = 0xFFFFFFFF;
    mapping(address => uint) private accountData;

    address private nominatedAdmin;
    address private admin;
    mapping(address => bool) private verifiers;

    // uint public constant EPOCH_DURATION = 3; // 3 seconds
    uint public constant EPOCH_DURATION = 86400; // 1 day
    uint public constant EPOCH_COIN_ISSUANCE = 1000000 * 1e18; // 1M tokens/day
    mapping(uint => uint) private epochPointTotal;

    address public token;

    bool private migrated = false;

    event Checkin(address indexed user, uint indexed epoch, address indexed referrer, uint streak, uint points, uint coins);

    constructor(address tokenContract) public {
        admin = _msgSender();
        token = tokenContract;
    }

    function migrate(address legacyMonolithContract) public {
        require(!migrated, 'Already migrated');
        require(_msgSender() == admin, 'Not Admin');

        migrated = true;

        StreakPointsGame game = StreakPointsGame(legacyMonolithContract);

        address payable[30] memory legacyUsers = [
            0x07Cbf3171D5D1724424E72D404Aa01f292B905c3,
            0x15CaAB4b9ADBaFB0050A8D2fA5De68cD6AeBb6EE,
            0x1cC3195C46C2F6AF665Ae281ad861eAb88ed8Fb5,
            0x1f35E74d2bB0A43fE79cA376eaD63dA7c926e455,
            0x268DEc53B71A2e688638419e9A0Fc6204Cd716Ef,
            0x2992A8820B62623a9511911b810698a76B82BD47,
            0x30aC71B1a1b0384C4c8b17E87d863cC4A2f3db28,
            0x3d95D4A6DbaE0Cd0643a82b13A13b08921D6ADf7,
            0x4133c79E575591b6c380c233FFFB47a13348DE86,
            0x460988aF9Ff12C8085A1a5B636F26cC4C57dbCef,
            0x4ffa395F5F28F73fa0cc392767896b29aB185198,
            0x62Fd5B42153C6E6097dbF1E3df8DB0eFD8e64cee,
            0x80cFfdCA4d7E05Eb25e703A183E98C7a4094EeC0,
            0x81E5cd19323ce7f6b36c9511fbC98d477a188b13,
            0x852548338cd5A8DE1384FdE3bFc678A8669C0F4d,
            0xa1acaDDd259649d470B42C95738E5e89C8d8A233,
            0xA345e6794acF2CB5533e52e8B142bD6a5003b211,
            0xAC4a5d98736fB12a3423Edb7A8719dACe80E6d1a,
            0xb900Fc946a98cdc066e5efA5B4135F12f6936dE7,
            0xBA5fbA9E705f76d30e620607d76D18d3dcf9B2AB,
            0xc2F82A1F287B5b5AEBff7C19e83e0a16Cf3bD041,
            0xC6cD1A73fe649fEbBD2b400717c8CF5C5b5BFD8f,
            0xC76A2c3C1d4fC7c753AA91E281A07e3784450823,
            0xcC126fA2B35ccd634E8F62BE2E6CcF933527f8C8,
            0xdB603FA3AF8A964a2868e1eA16Fd3ECeF5A6FeE6,
            0xE23AB100EAB981b53Ee825F71Ee64a9113E6ad24,
            0xf4ACCDFA928bF863D097eCF4C4bB57ad77aa0cb2,
            0xF60aa01430f70D6aeCd8b049bBD40d53554f908c,
            0xfAb9a3D37999E12252b47468D2FFD4BE15936012,
            0xFeA35ce9f91b95d432136BFa8Dd0e647A4e8a713
        ];

        uint currentEpoch = getCurrentEpoch();

        // Migrate the previous and current epoch point total
        _addToEpochPoints(currentEpoch - 1, game.getEpochPointTotal(currentEpoch - 1));
        _addToEpochPoints(currentEpoch, game.getEpochPointTotal(currentEpoch));

        // Migrate all previous players
        for (uint i = 0; i < legacyUsers.length; i++) {
            address user = legacyUsers[i];
            Account memory account = _loadAccount(user);

            // These calls apply penalties if the user missed checkins
            account.points = game.getAccountPoints(user);
            account.currentStreak = game.getAccountCurrentStreak(user);

            // These calls simply read from the account state
            account.longestStreak = game.getAccountLongestStreak(user);
            uint lastCheckinEpoch = game.getAccountLastCheckinEpoch(user);
            if (currentEpoch - lastCheckinEpoch > 1) {
                // Hack: set last checkin to yesterday to prevent double penalization
                account.lastCheckinEpoch = currentEpoch - 1;
                account.lastCheckinPoints = 0;
            } else {
                account.lastCheckinEpoch = lastCheckinEpoch;
                account.lastCheckinPoints = account.points;
            }

            _saveAccount(user, account);

            // Migrate the coin balances
            uint coins = StreakPointsToken(legacyMonolithContract).balanceOf(user);
            if (coins > 0) {
                StreakPointsToken(token).mint(user, coins);
            }
        }
    }


    function _checkin(address user, uint epoch, address refUser) private {
        Account memory account = _loadAccount(user);
        Account memory refAccount = _loadAccount(refUser);

        uint elapsedEpochs = _penalizeAccount(account);
        require(elapsedEpochs > 0, 'Already checked in');

        bool validReferral = account.longestStreak == 0 && refAccount.longestStreak > 0;
        if (validReferral) {
            account.points++;
            refAccount.points++;
            _saveAccount(refUser, refAccount);
        } else {
            refUser = address(0);
        }

        uint coins = _checkinAccount(account);
        if (coins > 0) {
            StreakPointsToken(token).mint(user, coins);
        }

        _addToEpochPoints(epoch, account.points);
        _saveAccount(user, account);

        emit Checkin(user, epoch, refUser, account.currentStreak, account.points, coins);
    }

    function checkin(uint epoch, address referrer, bytes memory signature) external {
        address user = _msgSender();

        require(epoch == getCurrentEpoch(), 'Checkin deadline missed');
        require(_isVerified(epoch, user, signature), 'Checkin not verified');

        _checkin(user, epoch, referrer);
    }

    function checkinBySignature(string memory epochStr, string memory userStr, string memory refUserStr, bytes memory userSig, bytes memory verifierSig) external {
        uint currentEpoch = getCurrentEpoch();
        bool hasReferrer = keccak256(abi.encodePacked(refUserStr)) != 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470; // hardcoded empty string hash
        bytes32 userHash = hasReferrer
            ? keccak256(abi.encodePacked('\x19Ethereum Signed Message:\n128StreakPoints checkin from ', userStr, ' id:', epochStr, ' ref:', refUserStr))
            : keccak256(abi.encodePacked('\x19Ethereum Signed Message:\n81StreakPoints checkin from ', userStr, ' id:', epochStr));

        uint epoch = StringParser._asciiBase10ToUint(epochStr);
        address user = StringParser._asciiBase16ToAddress(userStr);
        address refUser = hasReferrer ? StringParser._asciiBase16ToAddress(refUserStr) : address(0);

        require(user == ECDSA.recover(userHash, userSig), 'Checkin signature invalid');
        require(epoch == currentEpoch, 'Checkin deadline missed');
        require(_isVerified(epoch, user, verifierSig), 'Checkin not verified');

        _checkin(user, epoch, refUser);
    }

    function _isVerified(uint currentEpoch, address user, bytes memory signature) private view returns (bool) {
        bytes32 messageHash = ECDSA.toEthSignedMessageHash(keccak256(abi.encode(currentEpoch, user)));
        address signer = ECDSA.recover(messageHash, signature);
        return verifiers[signer];
    }

    function _loadAccount(address user) private view returns (Account memory) {
        uint data = accountData[user];
        return Account({
            points: (data >> 128) & BITMASK_32,
            currentStreak: (data >> 96) & BITMASK_32,
            longestStreak: (data >> 64) & BITMASK_32,
            lastCheckinEpoch: (data >> 32) & BITMASK_32,
            lastCheckinPoints: data & BITMASK_32
        });
    }

    function _saveAccount(address user, Account memory account) private {
        accountData[user] = account.lastCheckinPoints
            + (account.lastCheckinEpoch << 32)
            + (account.longestStreak << 64)
            + (account.currentStreak << 96)
            + (account.points << 128);
    }

    function _addToEpochPoints(uint epoch, uint points) private {
        epochPointTotal[epoch] += points;
    }

    function _penalizeAccount(Account memory account) private view returns (uint) {
        uint elapsedEpochs = getCurrentEpoch() - account.lastCheckinEpoch;
        if (elapsedEpochs > 1) {
            uint decay  = 2 ** (elapsedEpochs - 1);
            // halve points per missed day and reset streak
            if (decay != 0) {
                account.points = account.points / decay;
            }
            account.currentStreak = 0;
        }
        return elapsedEpochs;
    }

    function _checkinAccount(Account memory account) private view returns (uint) {
        uint epoch = getCurrentEpoch();
        uint coins = 0;
        if (account.currentStreak > 0) {
            coins = EPOCH_COIN_ISSUANCE * account.lastCheckinPoints / epochPointTotal[epoch - 1];
        }
        account.points++;
        account.currentStreak++;
        account.lastCheckinEpoch = epoch;
        account.lastCheckinPoints = account.points;
        if (account.currentStreak > account.longestStreak) {
            account.longestStreak = account.currentStreak;
        }
        return coins;
    }

    function _msgSender() internal override(Context, BaseRelayRecipient) view returns (address payable) {
        return BaseRelayRecipient._msgSender();
    }

    function addVerifier(address verifier) external {
        require(_msgSender() == admin, 'Not Admin');

        verifiers[verifier] = true;
    }

    function removeVerifier(address verifier) external {
        require(_msgSender() == admin, 'Not Admin');

        verifiers[verifier] = false;
    }

    function nominateAdmin(address nominee) external {
        require(_msgSender() == admin, 'Not Admin');

        nominatedAdmin = nominee;
    }

    function acceptAdmin() external {
        require(_msgSender() == nominatedAdmin, 'Address not nominated');

        admin = _msgSender();
        nominatedAdmin = address(0);
    }

    function getAccountPoints(address user) external view returns (uint) {
        Account memory account = _loadAccount(user);

        _penalizeAccount(account);

        return account.points;
    }

    function getAccountCurrentStreak(address user) external view returns (uint) {
        Account memory account = _loadAccount(user);

        _penalizeAccount(account);

        return account.currentStreak;
    }

    function getAccountLongestStreak(address user) external view returns (uint) {
        Account memory account = _loadAccount(user);

        return account.longestStreak;
    }

    function getAccountLastCheckinEpoch(address user) external view returns (uint) {
        Account memory account = _loadAccount(user);

        return account.lastCheckinEpoch;
    }

    function getAccountLastCheckinPoints(address user) external view returns (uint) {
        Account memory account = _loadAccount(user);

        return account.lastCheckinPoints;
    }

    function getAccountCheckinReward(address user) external view returns (uint) {
        Account memory account = _loadAccount(user);

        _penalizeAccount(account);

        return _checkinAccount(account);
    }

    function getAccountIsCheckedIn(address user) external view returns (bool) {
        Account memory account = _loadAccount(user);

        uint elapsedEpochs = _penalizeAccount(account);

        return elapsedEpochs == 0;
    }

    function getCurrentEpoch() public view returns (uint) {
        return block.timestamp / EPOCH_DURATION;
    }

    function getCurrentEpochPointTotal() external view returns (uint) {
        return epochPointTotal[getCurrentEpoch()];
    }

    function getEpochPointTotal(uint epoch) external view returns (uint) {
        return epochPointTotal[epoch];
    }

    function getEpochTimeRemaining() external view returns (uint) {
        return EPOCH_DURATION * (getCurrentEpoch() + 1) - block.timestamp;
    }

    function getAddressIsVerified(address verifier) external view returns (bool) {
        return verifiers[verifier];
    }

    function getAdmin() external view returns (address) {
        return admin;
    }
}