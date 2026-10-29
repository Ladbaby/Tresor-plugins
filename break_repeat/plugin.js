const json = require('tresor/json.v1');
const encoding = require('tresor/encoding.v1');
const reminder = 'You have repeated the exact same message three times in a row. You appear to be stuck in a loop. Stop repeating yourself and take a different, concrete next step (or finish if the task is already done).';
// Anthropic-only content shapes identify the dialect. Anything else in
// messages[] is treated as OpenAI, the common superset for that key.
const ANTHROPIC_BLOCKS = ['tool_use', 'server_tool_use', 'mcp_tool_use', 'thinking', 'redacted_thinking', 'image'];
function detect(payload) {
  if ('contents' in payload) return 'gemini';
  if ('input' in payload) return 'openai_responses';
  if (Array.isArray(payload.messages)) {
    const anthropic = payload.messages.some(m => m && Array.isArray(m.content) && m.content.some(b => b && typeof b === 'object' && ANTHROPIC_BLOCKS.includes(b.type)));
    return anthropic ? 'anthropic' : 'openai';
  }
  return null;
}
function sorted(value) {
  if (!value || typeof value !== 'object' || value instanceof json.NumberToken) return value;
  if (Array.isArray(value)) return value.map(sorted);
  const out = {}; for (const key of Object.keys(value).sort()) Object.defineProperty(out,key,{value:sorted(value[key]),enumerable:true}); return out;
}
function scalar(value) { return value == null ? '' : typeof value === 'string' ? value : json.stringifyLossless(sorted(value)); }
function tool(name,args) { return {tool:scalar(name),args:scalar(args)}; }
function fingerprint(pieces) { return json.stringifyLossless(sorted(pieces)); }
// A null candidate is a barrier, never an empty fingerprint or a skipped turn.
function messagePieces(message,format) {
  const pieces=[];
  let meaningful=false;
  if (typeof message.content==='string') {
    if(message.content.length){pieces.push(message.content);meaningful=true;}
  } else if(Array.isArray(message.content)) {
    for(const b of message.content) {
      if(!b || typeof b!=='object')return null;
      if(['text','input_text','output_text'].includes(b.type)&&typeof b.text==='string') {
        if(b.text.length){pieces.push(b.text);meaningful=true;}
      } else if(format==='anthropic'&&['tool_use','server_tool_use','mcp_tool_use'].includes(b.type)&&typeof b.name==='string'&&b.input!==undefined) {
        pieces.push(tool(b.name,b.input));meaningful=true;
      } else if(b.type==='thinking'||b.type==='redacted_thinking') {
        // Thinking is excluded from repeat comparison: only its shape is checked.
        const valid=b.type==='thinking'?typeof b.thinking==='string':typeof b.data==='string';
        if(!valid)return null;
      } else return null;
    }
  } else if(message.content!=null)return null;
  if(message.tool_calls!==undefined) {
    if(format!=='openai'||!Array.isArray(message.tool_calls))return null;
    for(const c of message.tool_calls) {
      if(!c||c.type!=='function'||!c.function||typeof c.function.name!=='string'||typeof c.function.arguments!=='string')return null;
      pieces.push(tool(c.function.name,c.function.arguments));meaningful=true;
    }
  }
  // Legacy function calls are still assistant output, not empty content.
  if(message.function_call!==undefined) {
    const c=message.function_call;
    if(format!=='openai'||!c||typeof c.name!=='string'||typeof c.arguments!=='string')return null;
    pieces.push(tool(c.name,c.arguments));meaningful=true;
  }
  return meaningful?pieces:null;
}
function geminiPieces(message) {
  if(!Array.isArray(message.parts))return null;
  const pieces=[];
  for(const p of message.parts) {
    if(!p||typeof p!=='object')return null;
    // Images/audio and unknown part shapes must not compare as empty text.
    if(Object.keys(p).some(k=>!['text','functionCall','thought','thoughtSignature'].includes(k)))return null;
    // Thought parts are thinking output and never take part in comparison.
    if(p.thought===true||p.thought==='true')continue;
    if(typeof p.text==='string') {if(p.text.length)pieces.push(p.text);}
    else if(p.functionCall&&typeof p.functionCall.name==='string'&&p.functionCall.args!==undefined)pieces.push(tool(p.functionCall.name,p.functionCall.args));
    else return null;
  }
  return pieces.length?pieces:null;
}
function responseBoundary(item) {
  return item&&(['user','system','developer','tool'].includes(item.role)||['function_call_output','custom_tool_call_output','tool_call_output'].includes(item.type));
}
function responsesPieces(group) {
  const pieces=[];
  for(const item of group) {
    if(!item||typeof item!=='object')return null;
    if(item.type==='reasoning')continue;
    if(item.role==='assistant'&&(item.type===undefined||item.type==='message')) {
      const part=messagePieces(item,'openai_responses');if(!part)return null;pieces.push(...part);
    } else if(['function_call','tool_call','custom_tool_call'].includes(item.type)) {
      const args=item.type==='custom_tool_call'?item.input:item.arguments;
      if(typeof item.name!=='string'||typeof args!=='string')return null;
      pieces.push(tool(item.name,args));
    } else return null;
  }
  return pieces.length?pieces:null;
}
function lastTurns(payload,format) {
  const history=format==='gemini'?payload.contents:format==='openai_responses'?payload.input:payload.messages;
  if(!Array.isArray(history))return [];
  const out=[];
  for(let i=history.length-1;i>=0&&out.length<3;) {
    const m=history[i--];let pieces;
    if(format==='openai_responses') {
      if(responseBoundary(m))continue;
      const group=[m];
      while(i>=0&&!responseBoundary(history[i]))group.push(history[i--]);
      pieces=responsesPieces(group.reverse());
    } else {
      if(!m||typeof m!=='object')return [];
      if(m.role!==(format==='gemini'?'model':'assistant')) {
        if(['user','system','developer','tool','function'].includes(m.role))continue;
        return [];
      }
      pieces=format==='gemini'?geminiPieces(m):messagePieces(m,format);
    }
    if(!pieces)return [];
    out.push(fingerprint(pieces));
  }
  return out;
}
// Text already carried by a user turn, used to keep the reminder idempotent.
function userText(turn,kind) {
  if(!turn||typeof turn!=='object')return null;
  if(kind==='gemini')return Array.isArray(turn.parts)?turn.parts.filter(p=>p&&typeof p.text==='string').map(p=>p.text).join(''):null;
  if(typeof turn.content==='string')return turn.content;
  if(Array.isArray(turn.content))return turn.content.filter(b=>b&&typeof b.text==='string').map(b=>b.text).join('');
  return null;
}
// Extend the trailing user turn when there is one so a single user turn never
// becomes two consecutive user messages, which strict upstreams reject.
function appendUser(list,text,kind) {
  if(!Array.isArray(list))return;
  const tail=list[list.length-1];
  if(tail&&typeof tail==='object'&&tail.role==='user') {
    const existing=userText(tail,kind);
    if(typeof existing==='string'&&existing.includes(text))return;
    if(kind==='gemini') {tail.parts=Array.isArray(tail.parts)?tail.parts:[];tail.parts.push({text});return;}
    const blockType=kind==='responses'?'input_text':'text';
    const blocks=Array.isArray(tail.content)?tail.content.slice():typeof tail.content==='string'?[{type:blockType,text:tail.content}]:[];
    blocks.push({type:blockType,text});tail.content=blocks;return;
  }
  if(kind==='gemini')list.push({role:'user',parts:[{text}]});
  else list.push({role:'user',content:text});
}
function request({body,context}) {
  let format=context&&context.formats?context.formats.current:null;
  let payload;try {payload=json.parseLossless(encoding.decode(body));}catch(_){return;}
  if(!payload||typeof payload!=='object'||Array.isArray(payload))return;
  format=format===null||format===undefined?detect(payload):format;
  if(!['openai','anthropic','openai_responses','gemini'].includes(format))return;
  const last=lastTurns(payload,format);if(last.length!==3||last[0]!==last[1]||last[1]!==last[2])return;
  if(format==='gemini')appendUser(payload.contents,reminder,'gemini');
  else if(format==='openai_responses')appendUser(payload.input,reminder,'responses');
  else if(format==='openai')appendUser(payload.messages,reminder,'openai');
  else appendUser(payload.messages,reminder,'anthropic');
  return {body:encoding.encode(json.stringifyLossless(payload))};
}
module.exports={request};
