import type { Balance } from '../hooks/useBalance'
import type { BridgeInfoState } from '../hooks/useBridgeInfo'
import type { Deposit } from '../hooks/useDeposit'
import type { Wallet } from '../hooks/useWallet'
import { BalanceRow } from '../components/BalanceRow'
import { CopyTextButton, Panel, PollNotice, Progress, Section } from '../components/ui'
import { DEPOSIT_STEPS, depositStage } from '../lib/status'
import { DEMO } from '../config'
type Props = { d: Deposit; wallet: Wallet; balance: Balance; bridge: BridgeInfoState; onConnect: () => void }
export function DepositView({ d, wallet, balance, bridge, onConnect }: Props) {
  const record = d.status.data ?? d.issued
  const stage = record && depositStage(record)
  return <div className="cw-grid"><div className="cw-col">
    <Section i={0}><div className="fld"><span className="lbl">Receive cwXMR on Sepolia</span><output className="ro-box">{wallet.address ?? 'Connect your recipient wallet'}</output><div className="help">Each issued Monero subaddress is bound to this recipient. No memo is required.</div></div></Section>
    <Section i={1}><div className="fld"><span className="lbl">Send stagenet XMR</span>{d.issued ? <><div className="val mono">{d.issued.depositAddress}</div><CopyTextButton text={d.issued.depositAddress} label="Copy address"/><div className="help">{DEMO ? 'SIMULATION: do not send any funds to this example address.' : 'Send only Monero stagenet XMR to this issued address.'}</div></> : <><div className="val empty">No deposit address issued</div>{!wallet.connected ? <button className="btn btn-p" onClick={onConnect}>Connect wallet</button> : <button className="btn btn-p" disabled={!!d.blockReason || d.busy} onClick={d.create}>{d.busy ? 'Issuing…' : 'Create deposit intent'}</button>}</>}{d.blockReason && <div className="help">{d.blockReason}</div>}{d.error && <Panel kind="alert" title={d.error}/>}</div></Section>
    <Section i={2}><BalanceRow balance={balance} connected={wallet.connected}/></Section>
  </div><div className="cw-col"><Section i={3}><div className="fld"><span className="lbl">Deposit progress</span>{record ? <><PollNotice poll={d.status}/>{stage?.kind === 'progress' && <Progress label="Deposit progress" steps={DEPOSIT_STEPS} current={stage.step} detail={stage.detail}/>} {stage?.kind === 'done' && <Panel kind="check" title="Mint reported complete" detail="Reveal your confidential balance to check it."/>}{stage?.kind === 'panel' && <Panel kind={stage.panel} title={stage.title} detail={stage.detail}/>}<div className="help">Keep your intent ID private. It reveals the recipient mapping.</div><CopyTextButton text={record.intentId} label="Copy private intent ID"/></> : <Panel kind="info" title="Create an intent to start" detail={bridge.info?.readiness_reason || 'Only backend-issued addresses may be used for deposits.'}/>}</div></Section><Section i={4}><div className="help">Stagenet / Sepolia proof of concept. The bridge relies on explicitly trusted network nodes. Vaults learn deposit amounts and recipient mappings. Browser enclave identity verification is still required before live actions.</div></Section></div></div>
}
