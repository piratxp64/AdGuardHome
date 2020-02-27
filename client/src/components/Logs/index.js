import React, { Component, Fragment } from 'react';
import PropTypes from 'prop-types';
import escapeRegExp from 'lodash/escapeRegExp';
import endsWith from 'lodash/endsWith';
import { Trans, withNamespaces } from 'react-i18next';

import { TABLE_DEFAULT_PAGE_SIZE } from '../../helpers/constants';

import PageTitle from '../ui/PageTitle';
import Loading from '../ui/Loading';
import Filters from './Filters';
import Table from './Table';
import Disabled from './Disabled';

import './Logs.css';

const TABLE_FIRST_PAGE = 0;
const INITIAL_REQUEST = true;
const INITIAL_REQUEST_DATA = ['', TABLE_FIRST_PAGE, INITIAL_REQUEST];

class Logs extends Component {
    componentDidMount() {
        this.props.setLogsPage(TABLE_FIRST_PAGE);
        this.getLogs(...INITIAL_REQUEST_DATA);
        this.props.getFilteringStatus();
        this.props.getLogsConfig();
    }

    getLogs = (older_than, page, initial) => {
        if (this.props.queryLogs.enabled) {
            this.props.getLogs({
                older_than, page, pageSize: TABLE_DEFAULT_PAGE_SIZE, initial,
            });
        }
    };

    refreshLogs = () => {
        this.getLogs(...INITIAL_REQUEST_DATA);
    };

    toggleBlocking = (type, domain) => {
        const { t, filtering: { userRules } } = this.props;
        const lineEnding = !endsWith(userRules, '\n') ? '\n' : '';
        const baseRule = `||${domain}^$important`;
        const baseUnblocking = `@@${baseRule}`;
        const blockingRule = type === 'block' ? baseUnblocking : baseRule;
        const unblockingRule = type === 'block' ? baseRule : baseUnblocking;
        const preparedBlockingRule = new RegExp(`(^|\n)${escapeRegExp(blockingRule)}($|\n)`);
        const preparedUnblockingRule = new RegExp(`(^|\n)${escapeRegExp(unblockingRule)}($|\n)`);

        if (userRules.match(preparedBlockingRule)) {
            this.props.setRules(userRules.replace(`${blockingRule}`, ''));
            this.props.addSuccessToast(`${t('rule_removed_from_custom_filtering_toast')}: ${blockingRule}`);
        } else if (!userRules.match(preparedUnblockingRule)) {
            this.props.setRules(`${userRules}${lineEnding}${unblockingRule}\n`);
            this.props.addSuccessToast(`${t('rule_added_to_custom_filtering_toast')}: ${unblockingRule}`);
        }

        this.props.getFilteringStatus();
    };

    renderBlockingButton(isFiltered, domain) {
        const buttonClass = isFiltered ? 'btn-outline-secondary' : 'btn-outline-danger';
        const buttonText = isFiltered ? 'unblock_btn' : 'block_btn';
        const buttonType = isFiltered ? 'unblock' : 'block';

        return (
            <div className="logs__action">
                <button
                    type="button"
                    className={`btn btn-sm ${buttonClass}`}
                    onClick={() => this.toggleBlocking(buttonType, domain)}
                    disabled={this.props.filtering.processingRules}
                >
                    <Trans>{buttonText}</Trans>
                </button>
            </div>
        );
    }

    render() {
        const {
            t,
            filtering,
            setLogsPage,
            setLogsPagination,
            setLogsFilter,
            queryLogs: {
                filter,
                enabled,
                processingGetConfig,
                processingAdditionalLogs,
                processingGetLogs,
                oldest,
                logs,
                pages,
                page,
            },
        } = this.props;

        const refreshButton = enabled ? (
            <button
                type="button"
                className="btn btn-icon btn-outline-primary btn-sm ml-3"
                onClick={this.refreshLogs}
            >
                <svg className="icons">
                    <use xlinkHref="#refresh" />
                </svg>
            </button>
        ) : (
            ''
        );

        return (
            <Fragment>
                <PageTitle title={t('query_log')}>
                    {refreshButton}
                </PageTitle>
                {enabled && processingGetConfig && <Loading />}
                {enabled && !processingGetConfig && (
                    <Fragment>
                        <Filters
                            filter={filter}
                            processingGetLogs={processingGetLogs}
                            processingAdditionalLogs={processingAdditionalLogs}
                            setLogsFilter={setLogsFilter}
                        />
                        <Table
                            logs={logs}
                            pages={pages}
                            page={page}
                            oldest={oldest}
                            filtering={filtering}
                            processingGetLogs={processingGetLogs}
                            processingGetConfig={processingGetConfig}
                            setLogsPagination={setLogsPagination}
                            setLogsPage={setLogsPage}
                            getLogs={this.getLogs}
                        />
                    </Fragment>
                )}
                {!enabled && !processingGetConfig && (
                    <Disabled />
                )}
            </Fragment>
        );
    }
}

Logs.propTypes = {
    getLogs: PropTypes.func.isRequired,
    queryLogs: PropTypes.object.isRequired,
    dashboard: PropTypes.object.isRequired,
    getFilteringStatus: PropTypes.func.isRequired,
    filtering: PropTypes.object.isRequired,
    setRules: PropTypes.func.isRequired,
    addSuccessToast: PropTypes.func.isRequired,
    getClients: PropTypes.func.isRequired,
    getLogsConfig: PropTypes.func.isRequired,
    setLogsPagination: PropTypes.func.isRequired,
    setLogsFilter: PropTypes.func.isRequired,
    setLogsPage: PropTypes.func.isRequired,
    t: PropTypes.func.isRequired,
};

export default withNamespaces()(Logs);
