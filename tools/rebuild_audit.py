"""Append-only local audit events for the rebuild and its subprocesses."""
import atexit,collections,datetime,hashlib,json,os,pathlib,re,sys,traceback,errno,warnings,argparse

_rejections={}
_hooks_installed=False


def emit(category,message,*,severity='info',context=None,exception=None):
    sink=os.environ.get('REBUILD_AUDIT_LOG')
    if not sink:return
    event=dict(time_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),stage=os.environ.get('REBUILD_AUDIT_STAGE','rebuild'),tool=pathlib.Path(sys.argv[0]).stem,category=category,severity=severity,message=str(message),context=context or {})
    if exception is not None:event.update(exception_type=type(exception).__name__,traceback=''.join(traceback.format_exception(type(exception),exception,exception.__traceback__)))
    line=json.dumps(event,default=str)+'\n'
    with pathlib.Path(sink).open('a',encoding='utf-8') as stream:stream.write(line)
    if severity in ('error','warning'):
        with pathlib.Path(sink).with_name('audit-errors.jsonl').open('a',encoding='utf-8') as stream:stream.write(line)


def record_exception(exception,context=None,*,category='item-error',severity='error'):
    emit(category,str(exception),severity=severity,context=context,exception=exception)


def reject(exception,context=None):
    """Count expected unsuccessful format/hash probes without per-probe I/O."""
    if not os.environ.get('REBUILD_AUDIT_LOG'):return
    message=re.sub(r'\b(?:0x[0-9a-fA-F]+|\d+)\b','<number>',str(exception));key=(type(exception).__name__,message,(context or {}).get('audit_site'))
    if key not in _rejections:_rejections[key]=dict(count=0,example_context=context or {},example_message=str(exception))
    _rejections[key]['count']+=1


@atexit.register
def flush_rejections():
    for (kind,message,site),details in _rejections.items():emit('expected-candidate-rejection',message,severity='rejection',context=dict(exception_type=kind,audit_site=site,**details))
    _rejections.clear()


def caught(exception,scope=None,*,expected=False,site=None):
    if not os.environ.get('REBUILD_AUDIT_LOG'):return
    context=dict(audit_site=site)
    if scope:
        for key in ('number','fid','pi','partition','base','off','offset','path','filename','source_offset','package'):
            if key in scope and isinstance(scope[key],(str,int,type(None),pathlib.Path)):context[key]=scope[key]
        for key in ('row','f'):
            value=scope.get(key)
            if isinstance(value,dict):context[key]={k:value[k] for k in ('record','id','path','source_offset','disk_offset','length','status') if k in value}
        if 'record' in scope:context['record']=str(scope['record'])
    message=str(exception).casefold();integrity=any(x in message for x in ('source mismatch','source frame revalidation','source revalidation','source differs','source changed','corpus mismatch','corpus differs','short source','protected input changed','previous placement changed'))
    operational=isinstance(exception,OSError) and exception.errno in ({errno.EACCES,errno.EPERM,errno.EIO,errno.ENOSPC,errno.EBADF} if expected else {errno.EACCES,errno.EPERM,errno.EIO,errno.ENOSPC,errno.EBADF,errno.ENOENT})
    if integrity or operational:record_exception(exception,context,category='integrity-error' if integrity else 'operational-error')
    elif expected:reject(exception,context)
    else:record_exception(exception,context,category='item-diagnostic',severity='warning')


def install_hooks():
    global _hooks_installed
    if _hooks_installed:return
    _hooks_installed=True;previous_warning=warnings.showwarning;previous_exception=sys.excepthook;previous_unraisable=sys.unraisablehook;previous_parse=argparse.ArgumentParser.parse_args
    def warning(message,category,filename,lineno,file=None,line=None):
        emit('runtime-warning',message,severity='warning',context=dict(warning_type=category.__name__,filename=filename,line=lineno));previous_warning(message,category,filename,lineno,file,line)
    def exception(kind,value,tb):
        record_exception(value,category='uncaught-tool-error');previous_exception(kind,value,tb)
    def unraisable(args):
        record_exception(args.exc_value,dict(message=args.err_msg,object=repr(args.object)),category='unraisable-tool-error');previous_unraisable(args)
    def parse(parser,args=None,namespace=None):
        result=previous_parse(parser,args,namespace);emit('parsed-arguments','Effective tool arguments and search bounds',context=vars(result));return result
    warnings.showwarning=warning;sys.excepthook=exception;sys.unraisablehook=unraisable;argparse.ArgumentParser.parse_args=parse


class Audit:
    def __init__(self,output,arguments=None):
        self.output=pathlib.Path(output);self.events=self.output/'audit-events.jsonl';self.errors=self.output/'audit-errors.jsonl';self.events.open('x',encoding='utf-8').close();self.errors.open('x',encoding='utf-8').close();self.arguments=arguments or {};self.finished=False
        self.environment=dict(os.environ,REBUILD_AUDIT_LOG=str(self.events.resolve()),REBUILD_AUDIT_STAGE='rebuild');self.previous={key:os.environ.get(key) for key in ('REBUILD_AUDIT_LOG','REBUILD_AUDIT_STAGE')};os.environ.update({key:self.environment[key] for key in self.previous})
        install_hooks()
        self.program={str(p.resolve()):hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path(__file__).parent.glob('*.py')}
        self.binaries={}
        for key in ('native','qemu_img','seven_zip','bit_repair_exe'):
            value=self.arguments.get(key)
            if value and pathlib.Path(value).is_file():self.binaries[str(pathlib.Path(value).resolve())]=hashlib.sha256(pathlib.Path(value).read_bytes()).hexdigest()
        if self.arguments.get('native'):
            helper=pathlib.Path(self.arguments['native']).parent/'repair_frame_bits.exe'
            if helper.is_file():self.binaries[str(helper.resolve())]=hashlib.sha256(helper.read_bytes()).hexdigest()
        emit('run-start','Forensic rebuild started',context=dict(arguments=arguments,program_sha256=self.program,binaries_sha256=self.binaries,python=sys.version))

    def child_environment(self,stage):return dict(self.environment,REBUILD_AUDIT_STAGE=stage)

    def finish(self,code,fatal=None):
        if self.finished:return
        self.finished=True
        if fatal is not None:record_exception(fatal,category='fatal-error')
        changed=[name for name,digest in (self.program|self.binaries).items() if not pathlib.Path(name).is_file() or hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()!=digest]
        if changed:emit('program-changed','Program sources changed during the run',severity='error',context=dict(paths=changed))
        flush_rejections();emit('run-end','Rebuild process ended',context=dict(exit_code=code,fatal=fatal is not None))
        counts=collections.Counter();groups={};total=0;rejected=0;parameters=[]
        with self.events.open(encoding='utf-8') as inp:
            for line in inp:
                row=json.loads(line);total+=1;counts[row['severity']]+=1
                if row['category']=='expected-candidate-rejection':rejected+=row['context']['count']
                if row['category']=='parsed-arguments':parameters.append(dict(stage=row['stage'],tool=row['tool'],arguments=row['context']))
                if row['severity'] not in ('error','warning'):continue
                key=(row['stage'],row['category'],row.get('exception_type'),row['message'])
                if key not in groups:groups[key]=dict(stage=key[0],category=key[1],exception_type=key[2],message=key[3],count=0,first_context=row['context'])
                groups[key]['count']+=1
        result=dict(schema_version=1,exit_code=code,fatal=fatal is not None,status='failed' if fatal is not None or code not in (0,2) else 'completed-with-errors' if counts['error'] else 'partial-rebuild-completed' if code==2 else 'completed',event_count=total,severity_counts=dict(counts),expected_rejected_candidate_count=rejected,error_and_warning_groups=list(groups.values()),effective_search_parameters=parameters,all_error_events=str(self.errors.resolve()),all_events=str(self.events.resolve()),program_sources_unchanged=not changed,arguments=self.arguments,scope='Operational/item exceptions and explicit input-corruption warnings retain full events and context. Expected unsuccessful format/hash probes are aggregated by exception class/message with counts and examples; they are not missing files or operational failures. Source-specific artifacts and per-stage logs remain local.')
        (self.output/'audit-summary.json').write_text(json.dumps(result,indent=2,default=str),encoding='utf-8')
        lines=[f"Rebuild audit: {result['status']}",f'Exit code: {code}',f"Errors: {counts['error']}; warnings: {counts['warning']}; expected rejected probes: {rejected}",f'Full error/warning events: {self.errors.resolve()}',f'All events: {self.events.resolve()}','']
        for group in groups.values():lines.append(f"[{group['stage']}] {group['category']} x{group['count']}: {group['message']}")
        (self.output/'audit-summary.log').write_text('\n'.join(lines)+'\n',encoding='utf-8')
        summary_path=self.output/'summary.json';summary=json.loads(summary_path.read_text()) if summary_path.exists() else dict(schema_version=1,rebuild_completed=False)
        summary.update(audit_summary=str((self.output/'audit-summary.json').resolve()),audit_log=str((self.output/'audit-summary.log').resolve()),audit_error_events=str(self.errors.resolve()),operational_error_count=counts['error'],warning_count=counts['warning'],program_sources_unchanged=not changed,process_exit_code=code)
        if fatal is not None:summary.update(rebuild_completed=False,fatal_error=dict(type=type(fatal).__name__,message=str(fatal)))
        summary_path.write_text(json.dumps(summary,indent=2,default=str),encoding='utf-8')
        for key,value in self.previous.items():
            if value is None:os.environ.pop(key,None)
            else:os.environ[key]=value
        return result


if os.environ.get('REBUILD_AUDIT_LOG'):install_hooks()
